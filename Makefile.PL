use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
my $define = $] >= 5.00467 ? '-DUSE_DEBUGGING_MSTATS' : '';

WriteMakefile(
    'NAME'	=> 'Devel::Peek',
    'VERSION_FROM'	=> 'Peek.pm',
    'LIBS'	=> [''],   # e.g., '-lm' 
    'DEFINE'	=> $define,     # e.g., '-DHAVE_SOMETHING' 
    'INC'	=> '',     # e.g., '-I/usr/include/other' 
    'dist' => {COMPRESS=>'gzip -9f', SUFFIX=>'gz'},
);
