# sftp2s3

Recursively *moves* files from SFTP to AWS S3. **NOTE the word *moves*, by default it will delete files off SFTP after confirming they are on S3.**

It is for those times when you need to repeatedly get files off a remote system and don't have shell access but do have SFTP access. Yeah, it seems rare, but it happens.

sftp2s3 is designed to be reliable and safe. It handles unreliable SFTP servers and networks, it can be interrupted, and it can be safely run repeatedly from cron.

## Requirements

sftp2s3 requires boto and paramiko, it is known to work with the versions provided by Ubuntu in 12.04+ (precise and trusty). It requires Python 2.7 (boto and paramiko don't support 3.x), it should work with Python 2.6 with argparse installed.

**Install with apt:**

* `apt-get install python-boto`
* `apt-get install python-paramiko`

**Install with pip:**

* `pip install boto`
* `pip install paramiko`

## Install

Just download from GitHub:

`git clone https://github.com/antoncohen/sftp2s3.git`

or

`curl -L -o sftp2s3.zip https://github.com/antoncohen/sftp2s3/archive/master.zip`

## Usage

Use `-h` or `--help` for usage. Use `--noop` to test without doing anything.

```
$ ./sftp2s3.py --help
usage: sftp2s3.py [-h] [--host HOST] [--port PORT] [--username USERNAME]
                  [--password PASSWORD] [--basepath BASEPATH]
                  [--pathmatch PATHMATCH] [--awskey AWSKEY]
                  [--awssecret AWSSECRET] [--bucket BUCKET]
                  [--awspath AWSPATH] [--nodelete] [--noop]
                  [--loglevel {debug,info,warning,error,critical}]

optional arguments:
  -h, --help            show this help message and exit
  --host HOST           SFTP hostname or IP
  --port PORT           SFTP port, default=22
  --username USERNAME   SFTP username, default=env variable
                        SFTP2S3_SFTP_USERNAME
  --password PASSWORD   SFTP password, default=env variable
                        SFTP2S3_SFTP_PASSWORD
  --basepath BASEPATH   SFTP base directory
  --pathmatch PATHMATCH
                        Regex, only matching files will be transferred,
                        optional, default='.*'
  --awskey AWSKEY       AWS API key, default=env variable SFTP2S3_AWS_KEY
  --awssecret AWSSECRET
                        AWS API secret, default=env variable
                        SFTP2S3_AWS_SECRET
  --bucket BUCKET       S3 bucket
  --awspath AWSPATH     Base S3 path to prepend to objects
  --nodelete            Disable deleting from SFTP
  --noop                No Op, disables download, upload, and delete
  --loglevel {debug,info,warning,error,critical}
                        Log level, default=warning
```

### Examples

Basic:


```
./sftp2s3.py --host 192.168.33.67 \
--username your_sftp_username \
--password your_sftp_password \
--bucket your_s3_bucket \
--awspath archive/files \
--basepath /path/to/sftp/files \
--pathmatch 'files/file[0-9]' \
--nodelete \
--loglevel info
```

More realistic:

```
HISTCONTROL=ignoreboth
 export SFTP2S3_SFTP_USERNAME='exampleco'
 export SFTP2S3_SFTP_PASSWORD='somepassword1'
 export SFTP2S3_AWS_KEY='AKIAIOSFODNN7EXAMPLE'
 export SFTP2S3_AWS_SECRET='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'

./sftp2s3.py --host cdn.provider.example.com \
--bucket logs.s3.example.com \
--awspath 'cdn/provider' \
--basepath './private/logs' \
--pathmatch 'logs/20[1-2][0-9]' \
--loglevel info
```

That will transfer files from ~/private/logs, if the file path contains 'logs/2010' to 'logs/2029'. The files will be put into the S3 bucket called 'logs.s3.example.com', under the path (object prefix) 'cdn/provider'. For example the file **sftp://cdn.provider.example.com/home/exampleco/private/logs/2014/08/file.log** will become **s3://logs.s3.example.com/cdn/provider/2014/08/file.log**.

### Options

**-h, --help**

Show the help message and exit.

**--host HOST**

SFTP hostname or IP, e.g., `--host sftp.exmaple.com`.

**--port PORT**

SFTP port, e.g., `--port 2222`.

Default = 22

**--username USERNAME**

SFTP username, e.g., `--username jsmith`.

Default = The environment variable SFTP2S3_SFTP_USERNAME

**--password PASSWORD**

SFTP password, e.g., `--password 'N5)f3lV6*@n'`.

For security this should be set as an environment variable so it doesn't show up in the process list.

Default = The environment variable SFTP2S3_SFTP_PASSWORD

**--basepath BASEPATH**

The base directory on the SFTP server to start moving files from, i.e., `cd` to this directory before doing any work. Can be relative or full path, e.g., `--basepath logs` or `--basepath ./logs` or `--basepath /home/foo/logs`.

Default = No base path, start in home directory

**--pathmatch PATHMATCH**

Regex, only transfer files that match this regex. They are matched against the SFTP server's version of the full path, but not anchored at the beginning. For example `--pathmatch 'logs/20[0-9][0-9]'` will match the file /home/foo/logs/2014/08/file.log but not /home/foo/logs/tmp/file.log.

default='.*' (match anything)

**--awskey AWSKEY**

AWS API key, e.g., `--awskey 'AKIAIOSFODNN7EXAMPLE'`.

Default = The environment variable SFTP2S3_AWS_KEY

**--awssecret AWSSECRET**

AWS API secret, e.g., `--awssecret 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'`.

For security this should be set as an environment variable so it doesn't show up in the process list.

Default = The environment variable SFTP2S3_AWS_SECRET

**--bucket BUCKET**

Plain S3 bucket name, without scheme or path, e.g., `--bucket my-s3-bucket-example`.

**--awspath AWSPATH**

Path to prepend to S3 objects. This is basically the folder on S3 to put files in, e.g., `--awspath some/logs`.

**--nodelete**

Disable deleting from SFTP, i.e., copy not move.

**--noop**

No operation. Disables download, upload, and delete. Good for testing authentication and pathmatch, will still go through and list all the files.

**--loglevel {debug,info,warning,error,critical}**

Set the verbosity. By default it is designed to be quiet unless something goes wrong, so it can be run daily from cron. To see what is happening, like files found, uploaded, etc., set `--loglevel info`

Default = warning

## Known Issues

* Doesn't delete empty directories after moving files to S3
* Doesn't support SSH key-based authentication
* No tests :(

## What it is not

* sftp2s3 is not a utility to transfer individual files to S3, just do that manually.
* sftp2s3 is not a sync utility (rsync, s3cmd sync), it *moves* files from SFTP to S3, but never deletes files from S3 (it will overwrite existing objects if the S3 MD5 doesn't match the MD5 of the file downloaded from SFTP.

## License

MIT

## Author

* Anton Cohen <anton@antoncohen.com>
* [Source](https://github.com/antoncohen/sftp2s3)
* [Homepage](http://www.antoncohen.com/)
* [@antoncohen](http://twitter.com/antoncohen)