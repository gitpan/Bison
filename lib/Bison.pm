package Bison;

=head1 NAME

Bison - IPTables Script generator

=head1 DESCRIPTION

First, Bison is under HEAVY development. I've released it because I'm lazy and don't have 
any version control of my own. So, sorry about that.
It can be used to generate a firewall script for your Linux box. It doesn't run the commands for you 
but generates the needed commands for you to run based on the methods you pass. It's also a lot of 
fun to build them.

=head1 SYNOPSIS

The synopsis is basic. All the methods have been exported. So a simple firewall script would be:

    package MyFirewall;
    
    use Bison;
    
    initfw(); # this will be called when you use Bison in later releases
    
    override_global({ip_address => '10.1.1.5'});
    default_policy({
        INPUT   => 'DROP',
        FORWARD => 'ACCEPT'
        OUTPUT  => 'ACCEPT',
    });
    
    drop_bad_tcp_flags();
    
    bison_finish(); 

Obviously the above script would lock you out of your system. But it shows it's a lot easier to write a bit 
of Perl than remember long-winded IPTables commands.

=cut

use warnings;
use strict;
use 5.010;

use vars qw/$bopts/;
our $VERSION = '0.01';

our $bopts = {
    ipt      => '/sbin/iptables',
    dry      => 0,
    iface    => 'eth0',
    ip_is    => 'dynamic',
    errors   => [],
    buffer   => [],
    firewall => 'bison'
};

use base 'Exporter';
our @EXPORT = qw/
    initfw
    flush
    override_global
    getvars
    default_policy
    bison_finish
    source_nat
    preroute
    chain_create
    log_setup
    accept_local
    accept_all_from
    drop_bad_tcp_flags
    drop_icmp
    open_service
    enable_ip_forwarding
/;

=head2 initfw

This function should be called before anything else.
It sets up the default firewall chain and a catchall filter.

=cut

sub initfw {
    my $args = shift;
    # create main bison chain
    chain_create($bopts->{firewall}, { jump => 'drop' });
    log_setup($bopts->{firewall});

    # now the catchall filter, known as dropwall
    chain_create('dropwall', { jump => 'drop'});
    log_setup('dropwall', { prefix => 'Bison DropWall'});
}

sub has_ip_address {
    if (! defined $bopts->{ip_address}) {
        die "Can't continue. No IP Address set. Please set one with override_globals({ip_address => '0.0.0.0'})\n";
    }
}

=head2 drop_bad_tcp_flags

Catches any malicious TCP packets into a badflags chain, then prefixes the log as that chain.
Should help prevent force fragment and XMAS packets. Also checks to make sure new TCP connections 
are SYN packets.
This section could do with a bit more work, but this is still a beta release :)

=cut

sub drop_bad_tcp_flags {
    my ($chain, $prefix) = @_;

    $chain = $chain||'badflags';
    $prefix = $prefix||'Bison BadFlags';
    ($bopts->{badflags}, $bopts->{badflags_prefix}) = ($chain, $prefix);
    # create a chain to handle them
    chain_create($chain, { jump => 'drop' });

    # add alert options with defaults
    log_setup($chain, { prefix => $prefix});

    ipt("-A INPUT -p tcp ! --syn -m state --state NEW -j $chain");
    ipt("-A INPUT -f -j $chain");
    ipt("-A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j $chain");
    ipt("-A INPUT -p tcp --tcp-flags ALL ALL -j $chain");
    ipt("-A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j $chain");
    ipt("-A INPUT -p tcp --tcp-flags ALL NONE -j $chain");
    ipt("-A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j $chain");
    ipt("-A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j $chain");
    return 1;
}

=head2 open_service

Open ports to a service by name (www, ssh, ftp). If no arguments are passed 
it will open access to everyone. If you pass a hash with to => then the port 
will be only available to that ip address.

=cut

sub open_service {
    my ($service, $args) = @_;

    my @services = qw/ssh www ftp/;
    if (! grep { $_ eq $service } @services) {
        log_error("open_service: No such service $service");
        return 0;
    }

    my ($to, $port);
    for(keys %$args) {
        $to = $args->{$_} if $_ eq 'to';
    }

    given(lc $service) {
        when ('ssh') { $port = 22; }   
        when ('www') { $port = 80; }
        when ('ftp') { $port = '20:21'; }
    }
    
    if ($to) { ipt("-A INPUT -i $bopts->{iface} -s $to -d 0/0 -p tcp --dport $port -j ACCEPT"); }
    else { ipt("-A INPUT -i $bopts->{iface} -s 0/0 -d 0/0 -p tcp --dport $port -j ACCEPT"); } 

    return 1;
}

=head2 drop_icmp

Drops all ICMP requests, but opens a few by default.
If you pass an array it will only allow what is requested

    drop_icmp( [qw/0 8 11/] );

=cut

sub drop_icmp {
    my $args = shift;

    # drop all icmp requests, except a few
    # 0 - Echo Reply
    # 3 - Destination Unreachable
    # 11 - Time Exceeded
    # 8 - Echo
    if ($args) {
        if (ref $args eq 'ARRAY') {
            for (@$args) {
                if ($_ == 8) { ipt("-A INPUT -p icmp --icmp-type 8 -m limit --limit 1/second -j ACCEPT"); next; }
                ipt("-A INPUT -p icmp --icmp-type $_ -j ACCEPT");
            }
        }
    }
    else {
        ipt("-A INPUT -p icmp --icmp-type 0 -j ACCEPT");
        ipt("-A INPUT -p icmp --icmp-type 3 -j ACCEPT");
        ipt("-A INPUT -p icmp --icmp-type 11 -j ACCEPT");
        ipt("-A INPUT -p icmp --icmp-type 8 -m limit --limit 1/second -j ACCEPT");
        ipt("-A INPUT -p icmp -j $bopts->{firewall}");
    }
    return 1;
}

=head2 chain_create

Creates a new custom chain. If you pass a hash argument you can set things like 
a jump.

    chain_create('mynewchain', { jump => 'accept' });

=cut

sub chain_create {
    my ($chain, $args) = @_;

    ipt("-N $chain");
    
    if ($args) {
        for (keys %$args) {
            if ($_ eq 'jump') {
                my $jump = uc $args->{$_};
                ipt("-A $chain -j $jump");
            }
        }
    }

    return 1;
}

=head2 log_setup

Sets up logging for a chain. You can specify the time, duration and prefix.

    log_setup ('mychain', { time => 8, duration => 'minute', prefix => 'MyChain Log'});
    # 8 alerts per minute

=cut

sub log_setup {
    my ($chain, $args) = @_;

    $chain = 'INPUT' if ! defined $chain;
    my $prefix = 'Bison'; # default log prefix :D
    my $time = 15;
    my $duration = 'minute';

    for(keys %$args) {
        $prefix = $args->{$_} if $_ eq 'prefix';
        $time = $args->{$_} if $_ eq 'time';
        $duration = $args->{$_} if $_ eq 'duration';
    }

    ipt("-A $chain -m limit --limit $time/$duration -j LOG --log-prefix [$prefix]");
    return 1;
}

=head2 source_nat

Sources everything going out the interface to be the given IP address.

    source_nat({ as => '10.1.1.5'});

=cut

sub source_nat {
    my (%args) = @_;

    has_ip_address();

    my $ip_is = $bopts->{ip_is};
    if (%args) { $ip_is = $args{as}; }

    if ($ip_is eq 'static') { ipt("-t nat -A POSTROUTING -o $bopts->{iface} -j SNAT --to $bopts->{ip_address}"); }
    elsif ($ip_is eq 'dynamic') { ipt("-t nat -A POSTROUTING -o $bopts->{iface} -j MASQUERADE"); }
    else {
        log_error("Unknown IP Address type in source_nat: $ip_is");
        return 0;
    }

    return 1;
}
        

sub getvars {
    use Data::Dumper;
    say Dumper($bopts);
}

=head2 override_global

Overrides any default settings, and allows you to create new ones.

    override_global({ iface => eth0, ip_address => '10.1.1.6'});

=cut

sub override_global {
    my $opt = shift;
    for (keys %$opt) {
        say "-> Global override: $_ => $opt->{$_}";
        $bopts->{$_} = $opt->{$_};
    }
}

=head2 preroute

Preroute options. ie: route an incoming port to a specified IP in the nat

    preroute('ports', { ports => '22:25', proto => 'tcp', to => '10.1.1.9' });

=cut

sub preroute {
    my ($what, $args) = @_;

    if ($what eq 'ports') {
        my ($proto, $ports, $to);
        for (keys %$args) {
            $to    = $args->{$_} if $_ eq 'to';
            $ports = $args->{$_} if $_ eq 'ports';
            $proto = $args->{$_} if $_ eq 'proto';
        }

        if ((! $to || ! $ports)) {
            log_error("Prerouting ports needs to and ports attributes");
            return;
        }
        
        if ((! defined $proto || $proto eq 'all')) {
            ipt("-t nat -A PREROUTING -i $bopts->{iface} -p tcp --dport $ports -j DNAT --to $to");
            ipt("-t nat -A PREROUTING -i $bopts->{iface} -p udp --dport $ports -j DNAT --to $to");
        }
        else { ipt("-t nat -A PREROUTING -i $bopts->{iface} -p $proto --dport $ports -j DNAT --to $to"); }
        return 1;
    }
}
        

sub iface {
    my $iface = shift;

    say "-> Using interface $iface";
}

=head2 enable_ip_forwarding

Simply switches on IP forwarding in /proc/sys/net/ipv4/ip_forward, if 
your system supports it.

=cut

sub enable_ip_forwarding {
    if ($bopts->{dry}) { say "-> NAT enabled"; }
    else { system('echo 1 > /proc/sys/net/ipv4/ip_forward'); }
}

=head2 accept_local

Accept everything locally

=cut

sub accept_local {
    ipt('-A INPUT -i lo -j ACCEPT');
    return 1;
}

=head2 accept_all_from

Accept all incoming connections from a specific IP, or locally.
You can pass an array to allow multiple sources.

    accept_all_from('local');
    accept_all_from('10.1.1.5');
    accept_all_from([qw/10.1.1.4 10.1.1.5 10.1.2.7/]);

=cut

sub accept_all_from {
    my $args = shift;

    if (ref $args eq 'ARRAY') {
        for (@$args) {
            ipt("-A INPUT -s $_ -d 0/0 -p all -j ACCEPT");
        }
    }
    elsif ($args eq 'local') { ipt('-A INPUT -i lo -j ACCEPT'); }
    else { ipt("-A INPUT -s $args -d 0/0 -p all -j ACCEPT"); }

    return 1;
}

=head2 flush

Flushes specific chains, including nat and mangle.

    flush(); # flush everything
    flush([qw/INPUT FORWARD nat/])

=cut

sub flush {
    my $opts = shift;
    my $errors = 0;
    my @flush_items;
    if (ref $opts eq 'ARRAY') {
        for (@{$opts}) {
            given (uc $_) {
                when ('INPUT') { push @flush_items, $_; }
                when ('OUTPUT') { push @flush_items, $_; }
                when ('FORWARD') { push @flush_items, $_; }
                when ('MANGLE') { push @flush_items, $_; }
                when ('NAT') { push @flush_items, $_; }
                when ('CUSTOM') { push @flush_items, $_; }
            }
        }
    }
    elsif (ref $opts eq 'SCALAR') {
        if (! grep $_ eq $opts, [qw/INPUT OUTPUT FORWARD mangle nat custom/]) {
            die "Can't flush chain '$opts'. Not a valid chain";
        }
        push @flush_items, $opts;
    }
    elsif (! defined $opts) { @flush_items = qw/INPUT OUTPUT FORWARD mangle nat custom/; }

    my $item;
    for (@flush_items) {
        next if $_ eq ''||undef;
        $item = lc $_;
        if (($item eq 'nat' || $item eq 'mangle')) {
            if (ipt("-F -t $item")) {
                say "-> Flushing $item";
            }
            else { log_error("Could not flush $item"); $errors++; }
        }
        elsif ($item eq 'custom') {
            if (ipt("-X")) {
                say "-> Flushing custom chains (-X)";
            }
            else { log_error("Could not flush custom chains"); $errors++; }
        }
        else {
            $item = uc $item;
            if (ipt("-F $item")) {
                say "-> Flushing chain $item";
            }
            else { log_error("Could not flush chain $item"); $errors++; }
        }
    }
    return 1 if ! $errors;
}

sub ipt {
    my $cmd = shift;
    my $ipt = $bopts->{ipt};
    
    if ($bopts->{debug}) {
        say "[debug] $bopts->{ipt} $cmd";
    }

    #my $out = `$ipt $cmd 2>&1`;
    #if ($out ne '') {
    #    return 0;
    #}
    #else { return 1; }
    push @{$bopts->{buffer}}, $cmd;
    return 1;
}

sub log_error {
    my $err = shift;

    push (@{$bopts->{errors}}, $err);
} 

=head2 default_policy

Sets the default policy for the specified chain.

default_policy({
    INPUT   => 'DROP',
    FORWARD => 'DROP',
});

=cut

sub default_policy {
    my $opt = shift;

    my $policy;
    my @chains = qw/INPUT OUTPUT FORWARD/;
    for (keys %$opt) {
        $policy = uc $opt->{$_};
        if (! grep $_ eq $_, @chains) {
            log_error("No such chain: $_");
        }
        else {
            if (ipt("-P $_ $policy")) {
                say "-> Setting default policy for $_ to $policy";
                return 1;
            }
            else {
                log_error("Could not set default policy for $_ to $policy");
            }
        }
    }
}

=head2 bison_finish

Call this method last, and don't forget. It cleans everything up 
and checks for errors. Also, it can print out a list of the IPTables 
commands you need to generate your firewall script

=cut

sub bison_finish {
    my $errors = 0;
    if (@{$bopts->{errors}} > 0) { $errors = @{$bopts->{errors}} }

    if ($errors > 0) {
        say "Errors";
        my $i;
        say "---";
        for (@{$bopts->{errors}}) {
            $i++;
            say "$i: $_";
        }
    }
    else { say "No problems occurred"; }

    # read buffer
    unless (! $bopts->{verbose}) {
        my $i = 0;
        for (@{$bopts->{buffer}}) {
            $i++;
            say "$i: $_";
        }
    }
}

=head1 BUGS

Please e-mail brad@geeksware.net

=head1 AUTHOR

Brad Haywood <brad@geeksware.net>

=head1 COPYRIGHT & LICENSE

Copyright 2011 the above author(s).

This sofware is free software, and is licensed under the same terms as perl itself.

=cut

1; # End of Bison
