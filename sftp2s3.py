#!/usr/bin/env python

# Move files from SFTP to AWS S3
# https://github.com/antoncohen/sftp2s3

# Copyright (c) 2014 Anton Cohen
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the Software),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED AS IS, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.


import argparse
import base64
import binascii
import logging
import os
import re
import socket
from stat import S_ISDIR
from stat import S_ISREG
import sys
import tempfile
import time
import traceback

import boto
from boto.utils import compute_md5
import paramiko
from paramiko.ssh_exception import SSHException


class FastTransport(paramiko.Transport):
    """
    Subclass of paramiki.Transport the increases performance.

    window_size increased for 10x faster transfers.

    packetizer.REKEY_ changes for trasfers larger than 1GB.

    See: https://github.com/paramiko/paramiko/issues/175
    """
    def __init__(self, sock):
        super(FastTransport, self).__init__(sock)
        self.window_size = 2147483647
        self.packetizer.REKEY_BYTES = pow(2, 40)
        self.packetizer.REKEY_PACKETS = pow(2, 40)


def arg_parser():
    """Return a dictionary of command line arguments.

    :returns: a dictionary of command line arguments
    :rtype: dict
    """

    parser = argparse.ArgumentParser()

    # SFTP options
    parser.add_argument('--host', help="SFTP hostname or IP")
    parser.add_argument('--port', type=int, default=22,
                        help="SFTP port, default=22")
    parser.add_argument('--username',
                        default=os.environ.get('SFTP2S3_SFTP_USERNAME'),
                        help="""SFTP username,
                        default=env variable SFTP2S3_SFTP_USERNAME""")
    parser.add_argument('--password',
                        default=os.environ.get('SFTP2S3_SFTP_PASSWORD'),
                        help="""SFTP password,
                        default=env variable SFTP2S3_SFTP_PASSWORD""")
    parser.add_argument('--pkey',
                        default=os.environ.get('SFTP2S3_SFTP_PKEY'),
                        help="""SFTP private key,
                        default=env variable SFTP2S3_SFTP_PKEY""")
    parser.add_argument('--basepath', default='',
                        help="SFTP base directory")
    parser.add_argument('--pathmatch', default=r'.*',
                        help="""Regex, only matching files will be transferred,
                        optional, default='.*'""")
    # S3 options
    parser.add_argument('--awskey',
                        default=os.environ.get('SFTP2S3_AWS_KEY'),
                        help="""AWS API key,
                        default=env variable SFTP2S3_AWS_KEY""")
    parser.add_argument('--awssecret',
                        default=os.environ.get('SFTP2S3_AWS_SECRET'),
                        help="""AWS API secret,
                        default=env variable SFTP2S3_AWS_SECRET""")
    parser.add_argument('--bucket', help="S3 bucket")
    parser.add_argument('--awspath', default='',
                        help="Base S3 path to prepend to objects")
    # Debug options
    parser.add_argument('--nodelete', dest='delete', action='store_false',
                        help="Disable deleting from SFTP")
    parser.add_argument('--noop', action='store_true',
                        help="No Op, disables download, upload, and delete")
    parser.add_argument('--loglevel', choices=['debug', 'info', 'warning',
                                               'error', 'critical'],
                        default='warning',
                        help="Log level, default=warning")
    parser.add_argument('--logfile', default=None,
                        help="Log file to save logging output.")

    return vars(parser.parse_args())


def retry_s3_key(s3bucket, s3path, times=20, sleep=5):
    """Returns a boto.s3.key.Key object. Retries setting the S3 key, sleeps
    between attempts. This works around S3's eventual conistency. Raises an
    Exception it all attempts fail.

    :param s3bucket: S3 bucket from connection.
    :type: s3bucket: boto.s3.bucket.Bucket

    :param s3path: S3 object name.
    :type s3path: str

    :param times: Number of attempts to make, default=20.
    :type times: str

    :param sleep: Seconds to sleep between attempts, default=5.
    :type sleep: int

    :returns: S3 Key
    :rtype: boto.s3.key.Key

    :raises Exception: if unable to get key after all attempts
    """
    for count in range(times):
        s3key = s3bucket.get_key(s3path)
        if s3key:
            return s3key
        else:
            logging.warning('Failed to get s3key on attempt ' + str(count + 1)
                            + '. Trying again in ' + str(sleep) + ' seconds.')
            time.sleep(sleep)
    else:
        raise Exception('Failed to get s3key in ' + str(times) + ' attempts.')


def etag_to_md5(s3key=None, s3bucket=None, s3path=None):
    """Returns a tuple with the hex digest version of the md5 and the base64
    version of the md5. This is the format returns by Key.compute_md5.

    Requires either s3key OR s3bucket and s3path.

    :param s3key: S3 Key object.
    :type s3key: boto.s3.key.Key

    :param s3bucket: S3 bucket object.
    :type s3bucket: boto.s3.bucket.Bucket

    :param s3path: S3 object name.
    :type s3path: str

    :returns: A tuple with hex digest and base64 versions of md5 etag, or None
    :rtype: tuple
    """
    if not s3key:
        try:
            s3key = retry_s3_key(s3bucket, s3path)
        except Exception as e:
            logging.warning('ERROR getting key for etag: ' + str(s3path))
            logging.debug(str(e.__class__) + str(e))
            logging.debug(traceback.format_exc())
            return None

    if s3key.etag:
        match = re.compile('^"[a-fA-F0-9]{32}"$')
        if re.match(match, s3key.etag):
            # .etag has doublt quotes around it
            etag = s3key.etag.strip('"')
            md5 = (etag, base64.b64encode(binascii.unhexlify(etag)))
            return md5

    # If everything fails, return None
    return None


def sftp_files(path, sftp):
    """Generator that yields the full path of all regular files under path.

    :param path: Full base path to start serach from.
    :type path: str

    :param sftp: paramiko.SFTPClient object.
    :type sftp: paramiko.SFTPClient

    :returns: A generator object containing strings (str) of full file paths
    :rtype: generator
    """
    dirs = [path]
    for d in dirs:
        dirlist = sftp.listdir_attr(d)
        for node in dirlist:
            fullpath = d + '/' + node.filename
            if S_ISDIR(node.st_mode):
                dirs.append(fullpath)
            elif S_ISREG(node.st_mode):
                logging.info('Found: ' + fullpath)
                yield fullpath


def filedata(files, sftp, pathmatch='.*', noop=False):
    """Generator that yields file path, data as a tempfile,
    and tuple containing the etag/md5.

    :param files: List of files to work with.
    :type files: list

    :param sftp: paramiko.SFTPClient object.
    :type sftp: paramiko.SFTPClient

    :param pathmatch: Regex to match files, use to exclude unwatched files.
    :type pathmatch: str

    :param noop: Enable No Op to not download the file.
    :type noop: bool

    :returns: A generator containing str, tempfile.NamedTemporaryFile, tuple
    :rtype: generator
    """
    match = re.compile(pathmatch)
    for filepath in files:
        if re.search(match, filepath):
            # boto will set content type by file suffix
            suffix = os.path.splitext(filepath)[1]
            data = tempfile.NamedTemporaryFile(suffix=suffix)
            if not noop:
                try:
                    # sftp.get checks file sizes, so we don't manually stat
                    sftp.get(filepath, data.name)
                    # Seek file cursor to beginning before md5
                    data.seek(0)
                    md5 = compute_md5(data)
                    logging.info('Local MD5: ' + str(md5))
                    yield filepath, data, (md5[0], md5[1])
                except IOError:
                    logging.warning('Error downloading: ' + filepath)
            else:
                logging.info('NOOP: Downloading from SFTP: ' + filepath)
                md5 = compute_md5(data)
                yield filepath, data, (md5[0], md5[1])


def s3_upload(s3bucket, fullpath, data, orig_md5, base, strip='/', noop=False):
    """Upload data to S3. Returns path to file on S3.

    :param s3bucket: S3 bucket object.
    :type s3bucket: boto.s3.bucket.Bucket

    :param fullpath: Full original path from SFTP server.
    :type fullpath: str

    :param data: File object to upload.
    :type data: tempfile.NamedTemporaryFile

    :param orig_md5: Tuple of the hex digest and base64 version of the md5.
    :type orig_md5: tuple

    :param base: Base path on S3.
    :type base: str

    :param strip: String to strip off the original fullpath.
    :type strip: str

    :param noop: Enable No Op, disables upload.
    :type noop: bool

    :returns: S3 file path (key) as str
    :rtype: str

    :raises IOError: if upload fails
    """
    sub = re.compile(strip)
    # Strip out extra slashes
    s3stub = re.sub(sub, '', fullpath, 1)
    s3path = base.strip('/') + '/' + s3stub.lstrip('/')
    if not noop:
        logging.info('Uploading to S3: ' + s3path)
        try:
            s3key = s3bucket.get_key(s3path) or s3bucket.new_key(s3path)
            etag_md5 = etag_to_md5(s3key=s3key)
            logging.info('existing etag: ' + str(etag_md5))
            logging.info('orig md5: ' + str(orig_md5))
            if etag_md5 != orig_md5:
                data.seek(0)
                s3key.set_contents_from_file(data)
            else:
                logging.info('Skipping upload, md5 matches: ' + s3path)
        except Exception as e:
            logging.warning('ERROR uploading: ' + s3path)
            logging.debug(str(e.__class__) + str(e))
            logging.debug(traceback.format_exc())
            raise IOError(s3path)
    else:
        logging.info('NOOP: Uploading to S3: ' + s3path)

    return s3path


def delete_from_sftp(sftp, fullpath, orig_md5, s3bucket, s3path, delete=False):
    """This function deletes from SFTP _only_ if the etag on S3 matches
    the md5 computed from SFTP. You must pass delete=True for it to work.
    Most of this function is redundant and only here to be extra safe before
    deleting. Returns nothing.

    :param sftp: paramiko.SFTPClient object.
    :type sftp: paramiko.SFTPClient

    :param fullpath: Full path to file on SFTP server.
    :type fullpath: str

    :param orig_md5: Tuple of the hex digest and base64 version of the md5.
    :type orig_md5: tuple

    :param s3bucket: S3 bucket object.
    :type s3bucket: boto.s3.bucket.Bucket

    :param s3path: Full path to object on S3.
    :type s3path: str

    :param delete: Enable actual deleting. Defaults to False.
    :type delete: bool
    """
    # This md5 check isn't strictly required, boto check the etag after
    # uploading, but just to be safe we check again.
    md5 = etag_to_md5(s3bucket=s3bucket, s3path=s3path)
    if delete is False:
        logging.info('Skipping deletion from SFTP: ' + fullpath)
    elif md5 == orig_md5 and delete is True:
        logging.info('Deleting from SFTP: ' + fullpath)
        try:
            sftp.remove(fullpath)
        except IOError as e:
            logging.warning('ERROR removing: ' + fullpath)
            logging.debug('Exception: ' + str(e.__class__) + str(e))
            logging.debug(traceback.format_exc())
    elif md5 != orig_md5:
        logging.warning('Warning md5s do not match: ' + fullpath +
                        ' orig_md5:' + str(orig_md5) +
                        ' md5:' + str(md5))
    else:
        logging.error('ERROR in delete_from_sftp, this code should never run.')


def sftp_connect(host, port, username, password=None, pkey=None):
    """Connects to SFTP and returns an SSH connection and SFTP client.
    Retries the SSH connection 10 times with a 5 second timeout per attempt.

    :param host: SFTP server hostname or IP.
    :type host: str

    :param port: SFTP server port.
    :type port: int

    :param username: SFTP username.
    :type username: str

    :param password: SFTP password.
    :type password: str

    :param pkey: SFTP private key path.
    :type pkey: str

    :returns: SSH connection and SFTP client
    :rtype: paramiko.SSHClient, paramiko.SFTPClient
    """
    # Retry SSH connection 10 times for unreliable SFTP servers
    tries = 10
    socket.setdefaulttimeout(5.0)
    for count in range(tries):
        try:
            ssh_conn = FastTransport((host, port))
            pkey_content = None
            if pkey is not None:
                pkey_content = paramiko.RSAKey.from_private_key_file(filename=pkey)
            ssh_conn.connect(username=username, password=password, pkey=pkey_content)
            sftp = paramiko.SFTPClient.from_transport(ssh_conn)
        except SSHException as e:
            if 'timed out' in e.__str():
                logging.warning('SFTP connection attempt ' + str(count + 1) +
                                ' failed, retrying...')
            else:
                raise
        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            logging.error('Unexpected error connecting to SFTP')
            raise
        else:
            break
    else:
        logging.error('Attempted to connect to ' + host + ':' + str(port) +
                      ' ' + str(tries) + ' times and failed.')
        sys.exit(10)

    return ssh_conn, sftp


def run(args, sftp, s3bucket):
    """Calls the download, upload, and delete functions. Returns nothing.

    :param args: Dictionary of command line arguments or defaults.
    :type args: dict

    :param sftp: paramiko.SFTPClient object.
    :type sftp: paramiko.SFTPClient object

    :param s3bucket: S3 bucket object.
    :type s3bucket: boto.s3.bucket.Bucket
    """
    # cd to path, and get the server's version of full path
    sftp.chdir(args['basepath'])
    sftppath = sftp.normalize('.')

    files = sftp_files(sftppath, sftp)

    for fullpath, data, orig_md5 in filedata(files, sftp,
                                             args['pathmatch'], args['noop']):
        logging.info('Working with: ' + fullpath)
        try:
            s3path = s3_upload(s3bucket, fullpath, data, orig_md5,
                               args['awspath'], sftppath, args['noop'])
        except IOError:
            logging.info('Not deleting due to error: ' + fullpath)
            continue
        else:
            # Doing noop check here because there will be no etag to check
            if args['delete'] and args['noop']:
                logging.info('NOOP: Deleting from SFTP: ' + fullpath)
            elif args['delete']:
                delete_from_sftp(sftp, fullpath, orig_md5,
                                 s3bucket, s3path, delete=args['delete'])
            else:
                logging.info('Skipping deletion from SFTP: ' + fullpath)
        finally:
            data.close()


def main():
    """Main function handles opening and closing connections,
    and sets up logging.
    """
    args = arg_parser()

    loglevel = getattr(logging, args['loglevel'].upper(), None)
    logging.basicConfig(filename=args['logfile'], format='%(asctime)s %(message)s', level=loglevel)

    logging.debug('Args: ' + str(args))

    try:
        # SFTP Connect
        ssh_conn, sftp = sftp_connect(args['host'], args['port'],
                                      args['username'], password=args['password'],
                                      pkey=args['pkey'])

        # S3 Connect
        s3 = boto.connect_s3(args['awskey'], args['awssecret'])
        s3bucket = s3.get_bucket(args['bucket'])
    except (KeyboardInterrupt, SystemExit):
        print 'Exiting...'
        sys.exit()
    except Exception as e:
        logging.error('ERROR connecting: ' + str(e.__class__) + str(e))
        logging.debug(traceback.format_exc())
        try:
            ssh_conn.close()
        except:
            pass
        sys.exit(1)

    try:
        run(args, sftp, s3bucket)
    except (KeyboardInterrupt, SystemExit):
        print 'Exiting...'
        sys.exit()
    finally:
        ssh_conn.close()


if __name__ == '__main__':
    main()
