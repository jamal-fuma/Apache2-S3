use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Apache2::S3',
    VERSION_FROM      => 'lib/Apache2/S3.pm', # finds $VERSION
    PREREQ_PM         => {
	'Digest::SHA1' => 0,
	'Digest::HMAC' => 0,
	'MIME::Base64' => 0,
    },
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Apache2/S3.pm', # retrieve abstract from module
       AUTHOR         => 'Iain Wade <iwade@optusnet.com.au>') : ()),
);
