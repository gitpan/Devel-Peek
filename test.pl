#!/usr/bin/perl -w

use Devel::Peek qw(:ALL);

$x = [0, 1, {'two' => 22, 2 => 222}, [3, "three", [3,3,3], { three => 'iii'}]];

Dump $x;
print STDERR "Refcount of \$x is ", SvREFCNT($x), "\n";
SvREFCNT_inc($x);
print STDERR "After increment refcount of \$x is ", SvREFCNT($x), "\n";
SvREFCNT_dec($x);
print STDERR "After decrement refcount of \$x is ", SvREFCNT($x), "\n";

print STDERR "Refcount of \$x is ", SvREFCNT($x), "\n";
print STDERR "After increment refcount of \$x is ", SvREFCNT(SvREFCNT_inc($x)), "\n";
print STDERR "After previous increment refcount of \$x still is ", SvREFCNT($x), "\n";
print STDERR "After decrement refcount of \$x is ", SvREFCNT(SvREFCNT_dec($x)), "\n";
print STDERR "After previous decrement refcount of \$x still is ", SvREFCNT($x), "\n";
my $sub = sub {'aaa'};
$closure = sub {$sub};
sub subr {1}
sub closure {$sub}
sub other::package {$sub}
sub prototyped (&@) {'aha'}

mstat("Point 1");

Dump(*subr);
Dump($sub);
Dump($closure);
Dump(\&subr);
Dump(\&closure);
Dump(\*closure);
Dump(\&other::package);
Dump(\&prototyped);
Dump(\&Dump);
Dump ($x, 10);
DumpArray (10, 1,2,3);
$a = "a\nb\b\n\r";
$a =~ s/^..//s;
Dump($a);

mstat("Point 2");

DumpWithOP($closure);
DumpProg;
DeadCode;
