#!/usr/bin/perl
use warnings;
#use strict;
use Data::Dumper;
use Scalar::Util qw(looks_like_number);
#use NetAddr::IP;
#use Net::IP::LPM;
#use Getopt::Std;
#use Cwd 'abs_path';
#use File::Basename;
use Excel::Writer::XLSX;
use vars qw($opt_c);
use v5.10.1;
#use DateTime::Format::Flexible;
#The major goal of the script is translate hillstone config to juniper srx config

# define variable
my $text;   # save all config
my @texts;  # save all config to array
my $n=0;    # line number for 1st cycle 
my $second_n = 0;  # line number for 2nd cycle
my $row=0;  # excel compare file line number
my $workbook; # excel compare file 
my $worksheet;
my $hillstone_format;
my $srx_format;
my %hilston_srx_services        = (
    FTP     => "junos-ftp",     Any     => "any",
    HTTP    => "junos-http",    HTTPS   => "junos-https",
    SSH     => "junos-ssh",     SYSLOG  => "junos-syslog",
    RDP     => "junos-rdp",     ICMP    => "junos-icmp-all",
);

sub get_netmask {
    my $netmask = "@_";
    my @netmasks = split (/\./, $netmask);
    my $array_num = @netmasks;
    my $bit_num = 0;
    RETURN_BIT_NUM:
    for (my $i=0; $i<$array_num; $i++) {
        my $factor = 7;
        my $sum = 0;
        if ($netmasks[$i] != 0) {
            while ($netmasks[$i] != $sum) {
                $sum += 2**$factor;
                $factor--;
                $bit_num++;
            }
        }
        elsif ($netmasks[$i] == 0) {
            last RETURN_BIT_NUM;
        }
    }
    return $bit_num;
}

sub set_compare {
    local ($hillstone_conf, $srx_conf) = @_;
    # remove the new line charter of every array elements
    chomp (@$hillstone_conf, @$srx_conf);
    # connect every array elements by new line 
    @$hillstone_conf    =   join ("\n", @$hillstone_conf);
    @$srx_conf          =   join ("\n", @$srx_conf);
    $worksheet->write( $row, 0, $hillstone_conf, $hillstone_format );
    $worksheet->write( $row, 1, $srx_conf, $srx_format );
    $row++;
    return;
}

sub set_address_books {
    local $address_book_name = "@_";
    local (@hillstone_config, @srx_config);
    push @hillstone_config, $texts[$n];
    $n++;
    until($texts[$n] eq "exit") {
        local @cells = split/\s+/, $texts[$n];
        push @hillstone_config, $texts[$n];
        given($cells[0]) {
            when ("ip") {
                print "set security address-book global address $address_book_name $cells[-1]\n";
                push @srx_config, "set security address-book global address $address_book_name $cells[-1]";
            }
            when ("range") {
                print "set security address-book global address $address_book_name range-address $cells[-2] to $cells[-1]\n";
                push @srx_config, "set security address-book global address $address_book_name range-address $cells[-2] to $cells[-1]";
            }
            when ("description") {
                print "set security address-book global address $address_book_name description $cells[-1]\n";
                push @srx_config, "set security address-book global address $address_book_name description $cells[-1]";
            }
        }   
        $n++;
    }
    push @hillstone_config, $texts[$n];
    if ( (@hillstone_config && @srx_config) && defined $opt_c ) {
        set_compare(\@hillstone_config, \@srx_config);
    }
    return;
}

sub set_services {
    local ($service_type, $service_name) = @_;  
    local (@hillstone_config, @srx_config);
    push @hillstone_config, $texts[$n];
    $n++;
    if ($service_type eq "service") {
        until ($texts[$n] eq "exit" ) {
            local @cells = split/\s+/, $texts[$n];
            local $cells_num = @cells;
            push @hillstone_config, $texts[$n];
            if ($cells_num == 3) {
                print "set applications application $service_name term $cells[0]-$cells[1]-$cells[2] protocol $cells[0] destination-port $cells[2]\n"; 
                push @srx_config, "set applications application $service_name term $cells[0]-$cells[1]-$cells[2] protocol $cells[0] destination-port $cells[2]\n"; 
            }
            elsif ($cells_num == 6) {
                print "set applications application $service_name term $cells[0]-$cells[1]-$cells[2] protocol $cells[0] destination-port $cells[2] source-port $cells[-2]-$cells[-1]\n";
                push @srx_config, "set applications application $service_name term $cells[0]-$cells[1]-$cells[2] protocol $cells[0] destination-port $cells[2] source-port $cells[-2]-$cells[-1]\n";
            }
            elsif ($cells_num == 7) {
                print "set applications application $service_name term $cells[0]-$cells[1]-$cells[2]-$cells[3] protocol $cells[0] destination-port $cells[2]-$cells[3] source-port $cells[-2]-$cells[-1]\n";
                push @srx_config, "set applications application $service_name term $cells[0]-$cells[1]-$cells[2]-$cells[3] protocol $cells[0] destination-port $cells[2]-$cells[3] source-port $cells[-2]-$cells[-1]\n";
            }
            elsif ($cells_num == 4) {
                print "set applications application $service_name term $cells[0]-$cells[1]-$cells[2]-$cells[3] protocol $cells[0] destination-port $cells[-2]-$cells[-1]\n"; 
                push @srx_config, "set applications application $service_name term $cells[0]-$cells[1]-$cells[2]-$cells[3] protocol $cells[0] destination-port $cells[-2]-$cells[-1]\n"; 
            }
            $n++;
        }
        push @hillstone_config, $texts[$n];
        if ( (@hillstone_config && @srx_config) && defined $opt_c ) {
            set_compare(\@hillstone_config, \@srx_config);
        }
    }
    elsif ($service_type eq "servgroup") {
        until ($texts[$n] eq "exit") {
            push @hillstone_config, $texts[$n];
            local @cells = split/\s+/, $texts[$n];
            print "set applications application-set $service_name application $cells[-1]\n";
            push @srx_config, "set applications application-set $service_name application $cells[-1]\n";
            $n++;
        }
        push @hillstone_config, $texts[$n];
        if ( (@hillstone_config && @srx_config) && defined $opt_c ) {
            set_compare(\@hillstone_config, \@srx_config);
        }
    }
    return;
}

sub set_polices {
    local $policy_id = "@_";
    local ( @hillstone_config, @srx_config );
    push @hillstone_config, $texts[$n];
    $n++;
    local ($action, $src_zone, $dst_zone, @src_address, @dst_address, @application);
    until($texts[$n] eq "exit") {
        push @hillstone_config, $texts[$n];
        local @cells = split/\s+/, $texts[$n];
        given($cells[0]) {
            when ("action") {
                $action = $cells[-1];   
            }
            when ("src-zone") {
                $src_zone = $cells[-1];
            }
            when ("dst-zone") {
                $dst_zone = $cells[-1];
            }
            when ("src-addr") {
                push @src_address, $cells[-1];
            }
            when ("dst-addr") {
                push @dst_address, $cells[-1];
            }
            when ("src-ip") {
                push @src_address, $cells[-1];
                print "set security address-book global address $cells[-1] $cells[-1]\n";
                push @srx_config, "set security address-book global address $cells[-1] $cells[-1]\n";
            }
            when ("dst-ip") {
                push @dst_address, $cells[-1];
                print "set security address-book global address $cells[-1] $cells[-1]\n";
                push @srx_config, "set security address-book global address $cells[-1] $cells[-1]\n";
            }
            when ("dst-host") {
                push @dst_address, $cells[-1];
                print "set security address-book global address $cells[-1] $cells[-1]\n";
                push @srx_config, "set security address-book global address $cells[-1] $cells[-1]\n";
            }
            when ("service") {
                push @application, $cells[-1];
            }
            when ( "src-range") {
                push @src_address, "range-$cells[-2]-$cells[-1]";
                print "set security address-book global address range-$cells[-2]-$cells[-1] range-address $cells[-2] to $cells[-1]\n";
                push @srx_config, "set security address-book global address range-$cells[-2]-$cells[-1] range-address $cells[-2] to $cells[-1]\n";
            }
            when ( "dst-range") {
                push @dst_address, "range-$cells[-2]-$cells[-1]";
                print "set security address-book global address range-$cells[-2]-$cells[-1] range-address $cells[-2] to $cells[-1]\n";
                push @srx_config, "set security address-book global address range-$cells[-2]-$cells[-1] range-address $cells[-2] to $cells[-1]\n";
            }
        }
        $n++;
    }
    push @hillstone_config, $texts[$n];
    # if source address, destination address, application and action not defined, the policy will not function in hilston, so ignore these rules
    # perl no longer support test array and hash by defined function, instead of if (@array or %hash)
    if (defined ($src_zone && $dst_zone && $action) && (@src_address && @dst_address && @application) && ($src_zone ne "any" && $dst_zone ne "any")) {
        print "set security policies from-zone $src_zone to-zone $dst_zone policy p_$policy_id match source-address [ @src_address ] destination-address [ @dst_address ] application [ @application ]\n";
        print "set security policies from-zone $src_zone to-zone $dst_zone policy p_$policy_id then $action\n";
        push @srx_config, "set security policies from-zone $src_zone to-zone $dst_zone policy p_$policy_id match source-address [ @src_address ] destination-address [ @dst_address ] application [ @application ]\n";
        push @srx_config, "set security policies from-zone $src_zone to-zone $dst_zone policy p_$policy_id then $action\n";
    }
    elsif (defined ($src_zone && $dst_zone && $action) && (@src_address && dst_address && @application) && ($src_zone eq "any" || $dst_zone eq "any")) {
        print "set security policies global policy p_$policy_id match source-address [ @src_address ] destination-address [ @dst_address ] application [ @application ]\n";
        print "set security policies global policy p_$policy_id match from-zone $src_zone to-zone $dst_zone\n";
        print "set security policies global policy p_$policy_id then $action\n";
        push @srx_config, "set security policies global policy p_$policy_id match source-address [ @src_address ] destination-address [ @dst_address ] application [ @application ]\n";
        push @srx_config, "set security policies global policy p_$policy_id match from-zone $src_zone to-zone $dst_zone\n";
        push @srx_config, "set security policies global policy p_$policy_id then $action\n";
    }
    elsif (!defined ($src_zone && $dst_zone) && (@src_address && @dst_address && @application) && defined $action) {
        print "set security policies global policy p_$policy_id match source-address [ @src_address ] destination-address [ @dst_address ] application [ @application ]\n";
        print "set security policies global policy p_$policy_id then $action\n";
        push @srx_config, "set security policies global policy p_$policy_id match source-address [ @src_address ] destination-address [ @dst_address ] application [ @application ]\n";
        push @srx_config, "set security policies global policy p_$policy_id then $action\n";
    }
    if ( (@hillstone_config && @srx_config) && defined $opt_c ) {
        set_compare(\@hillstone_config, \@srx_config);
    }
    undef $src_zone;
    undef $dst_zone;
    undef @src_address;
    undef @dst_address;
    undef @application;
    undef $action;
    return;
}

sub set_interface_zone {
    local $interface = "@_";
    local $port_num = (split/\//, $interface)[-1];
    $interface =~ s!aggregate!reth!;
    local (@hillstone_config, @srx_config);
    push @hillstone_config, $texts[$n];
    $n++;
    local $zone;
    until($texts[$n] eq "exit") {
        local @cells = split/\s+/, $texts[$n];
        push @hillstone_config, $texts[$n];
        given($cells[0]) {
            when ("aggregate") {
                $cells[-1] =~ s!aggregate!reth!;
                print "set interfaces xe-0/0/$port_num gigether-options redundant-parent $cells[-1]\n";
                print "set interfaces $cells[-1] redundant-ether-options redundancy-group 1\n";
                push @srx_config, "set interfaces xe-0/0/$port_num gigether-options redundant-parent $cells[-1]\n";
                push @srx_config, "set interfaces $cells[-1] redundant-ether-options redundancy-group 1\n";
            }
            when ("zone") {
                $zone = $cells[-1];
                print "set security zones security-zone $zone interfaces $interface\n";
                push @srx_config, "set security zones security-zone $zone interfaces $interface\n";
            }
            when ("ip") {
                local $cells_num = @cells;
                if ($cells_num == 4) {
                    local $ip = $cells[-2];
                    local $netmask = get_netmask($cells[-1]);
                    print "set interfaces $interface family inet address $ip/$netmask\n";
                    push @srx_config, "set interfaces $interface family inet address $ip/$netmask\n";
                }
            }
            when ("manage") {
                print "set security zones security-zone $zone interfaces $interface host-inbound-traffic system-services $cells[-1]\n"; 
                push @srx_config, "set security zones security-zone $zone interfaces $interface host-inbound-traffic system-services $cells[-1]\n"; 
            }
        }
        $n++;
    }
    push @hillstone_config, $texts[$n];
    if ( (@hillstone_config && @srx_config) && defined $opt_c ) {
        set_compare(\@hillstone_config, \@srx_config);
    }
    return;
}

sub set_route {
    local $routing_instance;
    local (@hillstone_config, @srx_config);
    push @hillstone_config, $texts[$second_n];
    $second_n++;
    until($texts[$second_n] eq "exit") {
        $routing_instance = "@_";
        local @cells = split/\s+/, $texts[$second_n];
        local $cells_num = @cells;
        push @hillstone_config, $texts[$second_n];
        given($cells[1]) {
            when ("route") {
                if ($cells_num == 4) {
                    print "set routing-instances $routing_instance routing-options static route $cells[-2] next-hop $cells[-1]\n";
                    push @srx_config, "set routing-instances $routing_instance routing-options static route $cells[-2] next-hop $cells[-1]\n";
                }
                elsif ($cells_num == 5) {
                    print "set routing-instances $routing_instance routing-options static route $cells[2] next-hop $cells[-1]\n";
                    push @srx_config, "set routing-instances $routing_instance routing-options static route $cells[2] next-hop $cells[-1]\n";
                }
                elsif ($cells_num == 7 && $cells[-2] eq "description") {
                    print "set routing-instances $routing_instance routing-options static route $cells[2] next-hop $cells[-3]\n";
                    print "edit routing-instances $routing_instance routing-options static\n";
                    print "annotate route $cells[2] $cells[-1]\n";
                    print "top\n";
                    push @srx_config, "set routing-instances $routing_instance routing-options static route $cells[2] next-hop $cells[-3]\n";
                    push @srx_config, "edit routing-instances $routing_instance routing-options static\n";
                    push @srx_config, "annotate route $cells[2] $cells[-1]\n";
                    push @srx_config, "top\n";
                }
            }
        }
        $second_n++;
    }
    print "set routing-instances $routing_instance instance-type virtual-router\n" if defined($routing_instance);
    if (defined $routing_instance) {
        push @srx_config, "set routing-instances $routing_instance instance-type virtual-router\n"; 
    }
    push @hillstone_config, $texts[$second_n];
    if ( (@hillstone_config && @srx_config) && defined $opt_c ) {
        set_compare(\@hillstone_config, \@srx_config);
    }
}

#The BEGIN part process some staff
BEGIN {
    if ($#ARGV < 0 || $#ARGV > 5) { die "\nUsage:\tperl hilston2srx.pl [ -c <compare-file.xlsx> ] <config.file>\n
        Flags:\t-c file for compare between hillstone and srx configuration\n"; }
    
    #getopts('c:', \%options); save options to hash %options
    getopts('c:');  #save options to Getopt::Std side effect sets $opt_*

    if (system("/usr/bin/dos2unix $ARGV[0]") != 0) {
        print "command failed!: dos2unix:\n";
        exit;
    }
    # save all content of config to a variable, we will process the variable instead of <>
    open my $config, '<', $ARGV[0] or die "can't open file:$!\n"; #open the config filehandle
    $text = do { local $/; <$config> };
    $text =~ s#\"##g;
    close $config;
}

# replace the ssg's predefine services with srx's predefine applications
while (($key, $value) = each %hilston_srx_services) {
    $text =~ s/\b$key\b/$value/gm;
}

if (defined $opt_c) {
    print "Creating excel for compare...\n";
    $workbook = Excel::Writer::XLSX->new( $opt_c ) or die "Can't open excel as $!\n";
    $hillstone_format = $workbook->add_format();
    $srx_format = $workbook->add_format();
    $hillstone_format->set_color( 'green' );
    $hillstone_format->set_align( 'left' );
    $hillstone_format->set_align( 'vjustify' );
    $hillstone_format->set_align( 'vcenter' );
    $hillstone_format->set_text_wrap();
    $srx_format->set_color( 'blue' );
    $srx_format->set_align( 'left' );
    $srx_format->set_align( 'vjustify' );
    $srx_format->set_text_wrap();
    $srx_format->set_align( 'vcenter' );
    $worksheet = $workbook->add_worksheet( 'hillstone&&srx' ) or die "Can't open excel table hilston and srx\n";
}
else {
    print "Compare not needed\n";
}

@texts = split(/\n/, $text);

# remove blank lines
@texts = grep { !/(^$|^\n$|^\s+$)/ } @texts;

# remove white at begein and end
@texts = map { s/^\s+|\s+$//gr } @texts;


# first cycle for address, service, rule, interface, zone

while ($texts[$n]) {
    my @configs = split/\s+/, $texts[$n];
    given($configs[0]) {
        when ("address") {
            set_address_books ($configs[-1]);       
        }
        when ($_ eq "service" || $_ eq "servgroup") {
            set_services ($configs[0], $configs[-1]);
        }
        when ("rule") {
            set_polices ($configs[-1]);
        }
        when ("interface") {
            set_interface_zone($configs[-1]);
        }
    }
    $n++;
}

# second cycle for route

while ($texts[$second_n]) {
    my @configs = split/\s+/, $texts[$second_n];
    my $routing_instance;
    given($configs[1]) {
        when ("vrouter") {
            set_route ($configs[-1]);
        }
    }
    $second_n++;
}

$workbook->close();

# the last jobs
END {
    print "set applications application traceroute-icmp term t1 protocol icmp\n";
    print "set applications application traceroute-icmp term t1 icmp-type 8\n";
    print "set applications application traceroute-icmp term t1 icmp-code 0\n";
    print "set applications application traceroute-udp term t1 protocol udp\n";
    print "set applications application traceroute-udp term t1 destination-port 33400-34000\n";
    print "set applications application SNMP term 1 protocol udp\n";
    print "set applications application SNMP term 1 destination-port 161-162\n";
    print "set applications application SNMP term 1 inactivity-timeout 30\n";
    print "set applications application SNMP term 2 protocol tcp\n";
    print "set applications application SNMP term 2 destination-port 161-162\n";
    print "set applications application SNMP term 2 inactivity-timeout 30\n";
    print "set applications application DNS term t1 alg dns\n";
    print "set applications application DNS term t1 protocol udp\n";
    print "set applications application DNS term t1 destination-port 53\n";
    print "set applications application DNS term t2 alg dns\n";
    print "set applications application DNS term t2 protocol tcp\n";
    print "set applications application DNS term t2 destination-port 53\n";
    print "set applications application-set TRACEROUTE application traceroute-icmp\n";
    print "set applications application-set TRACEROUTE application traceroute-udp\n";
}
