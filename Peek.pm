package Devel::Peek;
=head1 NAME

Devel::Peek - Shoot yourself in the foot. If you have gone that
far, you do not need any documentation.

=cut

require Exporter;
require DynaLoader;

@ISA = qw(Exporter DynaLoader);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
@EXPORT = qw(
	
);
# Other items we are prepared to export if requested
@EXPORT_OK = qw(
		Dump SvREFCNT SvREFCNT_inc SvREFCNT_dec
);
%EXPORT_TAGS = ('ALL' => \@EXPORT_OK);


bootstrap Devel::Peek;

# Preloaded methods go here.

# Autoload methods go after __END__, and are processed by the autosplit program.

1;
__END__
