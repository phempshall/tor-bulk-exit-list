#!/usr/bin/env perl

use strict;
use warnings;
use Digest::SHA;

###############################################################################
# Configuration

my $URL_TORBULKEXITLIST = "https://check.torproject.org/torbulkexitlist";

my $FILE_TORBULKEXITLIST_NEW = "/usr/share/torbulkexitlist/torbulkexitlist";
my $FILE_TORBULKEXITLIST_OLD = "/usr/share/torbulkexitlist/torbulkexitlist.old";

# iptables default add parameter ((A)ppend|(I)nsert)
my $IPTABLES_DEFAULT_ADD_PARAM = "A"; 

# use ip6tables, default 0 (false)
# Currently $URL_TORBULKEXITLIST does not provide IPv6 exit node addresses
my $USE_IPV6 = 0;

###############################################################################

run();

sub run {
	my @download_file = ("curl", "-o", $FILE_TORBULKEXITLIST_NEW, $URL_TORBULKEXITLIST);
	system(@download_file) == 0
	    or die "system @download_file failed: $?";

	open(my $fh_new, "<", $FILE_TORBULKEXITLIST_NEW)
	    or die "Can't open < $FILE_TORBULKEXITLIST_NEW: $!";
	    chomp(my @file_new_ips = <$fh_new>);
	close($fh_new);

	if (not -e $FILE_TORBULKEXITLIST_OLD) { # First run
		process_addrs( \@file_new_ips, $IPTABLES_DEFAULT_ADD_PARAM );
	}
	else {
		if (compare_file_hash()) {
			warn("INFO Tor Exit List UNCHANGED. Exiting.");
			exit();
		}

		open(my $fh_old, "<", $FILE_TORBULKEXITLIST_OLD)
		    or die "Can't open < $FILE_TORBULKEXITLIST_OLD: $!";
		    chomp(my @file_old_ips = <$fh_old>);
		close($fh_old);
		
		my @additions = not_in_first( \@file_old_ips, \@file_new_ips );
		process_addrs( \@additions, $IPTABLES_DEFAULT_ADD_PARAM );

		my @removed = not_in_first( \@file_new_ips, \@file_old_ips );
		process_addrs( \@removed, "D" );
	}

	rename $FILE_TORBULKEXITLIST_NEW, $FILE_TORBULKEXITLIST_OLD;

	exit();
} #end run()

sub compare_file_hash {
	my $hash_old = Digest::SHA->new("sha1")->addfile($FILE_TORBULKEXITLIST_OLD)->hexdigest;
	my $hash_new = Digest::SHA->new("sha1")->addfile($FILE_TORBULKEXITLIST_NEW)->hexdigest;

	return 1 if ($hash_old eq $hash_new)
		or return 0;
} #end compare_file_hash()

sub not_in_first {
    my ($first, $second) = @_;
    my %first = map{ $_ => undef } @$first;
    return grep { ! exists $first{$_} } @$second; 
} #end not_in_first()

sub process_addrs {
	my ($ip_addrs, $type) = @_;

	foreach my $ip (@$ip_addrs) {
		iptables($ip, $type);
	}
} #end process_addrs()

sub iptables {
	my ($ip, $type) = @_;

	my $exec;
	if (check_ip_addr_format($ip) eq "ipv4") {
		$exec = "iptables";
	}
	elsif (check_ip_addr_format($ip) eq "ipv6" && $USE_IPV6 == 1) {
		$exec = "ip6tables";
	}
	else { 
		warn("Invalid IP address format: $ip\n");
		return;
	}

	my $cmd_iptables = "$exec -$type INPUT -s $ip -j DROP";
	system($cmd_iptables) == 0
	    or die "system $cmd_iptables failed: $?";
} #end iptables()

sub check_ip_addr_format {
	my $ip = shift;

	if ($ip =~ m/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/) {
		return "ipv4";
	}
	elsif ($ip =~ m/^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$/) {
		return "ipv6";
	}
	else {
		return 0;
	}
} #end check_ip_addr_format()


__END__

=pod

=encoding UTF-8

=head1 NAME

torbulkexitlist.pl

=head1 SYNOPSIS

Create iptables rules for blocking Tor exit nodes using the Tor Bulk Exit List.

=head1 LICENSE

This library is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.

=head1 DISCLAIMER

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

=head1 AUTHOR

Paul Hempshall - <https://www.paulhempshall.com>

=head1 COPYRIGHT

Copyright 2022 Paul Hempshall

=head1 DESCRIPTION

Download Tor Bulk Exit List and create/update iptables rules for
blocking Tor exit nodes. Compares old and new files for updating firewall.

Can be automated with cron.

=over

=item $URL_TORBULKEXITLIST

URL of the Tor Bulk Exit List

=back

=over

=item $FILE_TORBULKEXITLIST_NEW

File location to read/write new Tor Bulk Exit List file

=back

=over

=item $FILE_TORBULKEXITLIST_OLD

File location to read/write old Tor Bulk Exit List file for comparision checks

=back

=over

=item $IPTABLES_DEFAULT_ADD_PARAM

Default parameter for adding iptables rules.

(A)ppend - default
(I)nsert

=back

=over

=item $USE_IPV6

Use ip6tables. Currently $URL_TORBULKEXITLIST does not provide IPv6 exit node addresses.
Disabled by default. Over-engineered future proofing.

(0) false - default.
(1) true.

=back

=over

=item run()

Main subroutine consisting on the the application proceedures.

=back

=over

=item compare_file_hash()

Compare file hashes of $FILE_TORBULKEXITLIST_OLD and $FILE_TORBULKEXITLIST_NEW using L<Digest::SHA>.

Returns true for a file match.

=back

=over

=item not_in_first()

Compares two arrays, returning values not found in the first array.

=back

=over

=item process_addrs()

Processes an array of addresses looping each array value. Calls L<$main::iptables> with each loop.

=back

=over

=item iptables()

Processes each $ip from caller L<$main::process_addrs>. Will call L<$main::check_ip_addr_format> 
to determine application executable (ip6tables/iptables).

Depends on configuration parameter: $USE_IPV6.

=back

=over

=item check_ip_addr_format()

Regex checking on the $ip values.

Returns "ipv4", "ipv6", or 0 (false).

=back

=cut