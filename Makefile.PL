use ExtUtils::MakeMaker;
@MM = ( NAME         => 'Devel::Peek',
        VERSION_FROM => 'Peek.pm',
        dist         => {COMPRESS=>'gzip -9f', SUFFIX=>'gz'},
      );

if ($ExtUtils::MakeMaker::VERSION >= 5.4301) {
    push @MM, CAPI => 'TRUE';
}

WriteMakefile(@MM);
