#------------------------------------------------------------#
# Scan For Open Shares                                       #
#                                                            #
# *script will scan for open shares and also                 #
#  recursively search any open shares for a                  #
#  filename that matches a regular expression                #
#  specified in the -r parameter.  Type opensh.pl            #
#  at a command prompt to see usage info.                    #
#                                                            #
#------------------------------------------------------------#
use strict;
no strict 'refs';
use warnings;
use Win32::Perms;
use Win32::NetAdmin;
use Win32::NetResource qw(:DEFAULT GetSharedResources GetError);
use Win32::AdminMisc;
use Getopt::Std;
use File::Find;
use Net::Ping;

#---------#
# Globals #
#---------#
my(%opts);
my($prompt) = 0;
my($regex) = "";
my(@machines);

my %PERM = (
    ''  =>  0,
    R   =>  1,
    W   =>  2,
    X   =>  3,
    D   =>  4,
    P   =>  5,
    O   =>  6,
    A   =>  7,
);

my %MAP = (
    'FILE_READ_DATA'    =>  'R',
    'GENERIC_READ'      =>  'R',
    'KEY_READ'          =>  'R',
    'DIR_READ'          =>  'R',

    'FILE_WRITE_DATA'   =>  'W',
    'KEY_WRITE'         =>  'W',
    'GENERIC_WRITE'     =>  'W',
    'FILE_APPEND_DATA'  =>  'W',
    'DIR_ADD_SUBDIR'    =>  'W',
    'DIR_ADD_FILE'      =>  'W',

    'DELETE'            =>  'D',
    'FILE_DELETE_CHILD' =>  'D',

    'FILE_EXECUTE'      =>  'X',
    'FILE_TRAVERSE'     =>  'X',
    'GENERIC_EXECUTE'   =>  'X',
    'DIR_TRAVERSE'      =>  'X',
    'DIR_EXECUTE'       =>  'X',

    'CHANGE_PERMISSION' =>  'P',

    'TAKE_OWNERSHIP'    =>  'O',

    'FILE_ALL_ACCESS'   =>  'A',
    'GENERIC_ALL'       =>  'A',
    'DIR_ALL_ACCESS'    =>  'A',
    'STANDARD_RIGHTS_ALL' => 'A',
    ''                  =>  '',
);

#------------------------------#
# Parse Command Line Arguments #
#------------------------------#
getopts('m:l:i:', \%opts);

#no passed machines
unless ( ( exists $opts{'m'} ) || ( exists $opts{'l'} ) || ( exists $opts{'i'} ) )
{
 Usage();
}

#specified both a single machine and list of machines
my @cnt = keys %opts;
if ( (scalar @cnt) > 1 )
{
  print "Can only specify one option.\n";
  Usage();
}

if ( exists $opts{'m'} )
{
  @machines = ("$opts{'m'}");
}elsif ( exists $opts{'l'} )
{
  open IN, "$opts{'l'}"
    or die "Can't open the list of machines to scan: $!\n";
  while (<IN>)
  {
    chomp;
    my($machine,$remark) = split /\s+/;
    if (substr($machine,0,2) eq "\\\\")
    {
      push @machines, substr($machine,2,);
    }else
    {
      push @machines, $machine;
    }
  }
  close IN;
}elsif ( exists $opts{'i'} )
{
  #ip address or range
  my $arg = $opts{'i'};
  if ($arg =~ /-/)
  {
    #a range of ip addresses
    open IP, ">iplist.txt"
       or die "Can't open the iplist.txt file: $!\n";

    my($oct1,$oct2,$oct3,$oct4) = split( /\./, $arg );
    my($low,$high) = split( /-/, $oct4 );
    if ($low eq "0") { $low = "1" }       #not net addy
    if ($high eq "255") { $high = "254" } #not broadcast
    for (my $i = $low; $i <= $high; $i++)
    {
      my $host = "$oct1.$oct2.$oct3.$i";
      my $p = Net::Ping->new();
      if ( $p->ping($host) )
      {
        print "$host alive...\n";
        print IP "$host\n";
        push @machines, $host;
      } else {
        print "$host dead...\n";
      }
    }
    close IP;
    print "\n\n";
  }else
  {
    @machines = ("$opts{'i'}");
  }
}

#------------------------------------------#
# Main: Get Shared Resources on Machine(s) #
#------------------------------------------#
foreach my $machine (@machines)
{
  print "Processing $machine...\n";

  open LOG, ">$machine.txt"
     or die "Can't open the log file for $machine: $!";

  if ( $opts{'m'} || $opts{'l'} )
  {
    print LOG "__________ $machine -- " . Win32::AdminMisc::GetHostAddress($machine) . " __________\n\n";
  }
  elsif ($opts{'i'})
  {
    print LOG "__________ $machine -- " . Win32::AdminMisc::GetHostName($machine) . " __________\n\n";
  }

  if ( GetSharedResources(my $resources,RESOURCETYPE_ANY,{ RemoteName => "\\\\$machine" }) )
  {
    foreach my $href (@$resources)
    {
      #get name of remote shared directory
      my $rmtshare = $href->{"RemoteName"};
      print "working on $rmtshare\n";
      #print LOG "\n+----------+\n";
      print LOG "$rmtshare\n";
      #print LOG "Permissions:\n";
      #ReportPerms( $rmtshare );
      #print LOG "\n";

      #recurse to match files
      #print LOG "=== sqlsp.log, setup.iss, .mdf, .ldf, .sql, .log, or .xml  Files ===","\n";
      #find(\&match_regex, $rmtshare);

    } #end href for()
  } #end GetSharedResources if()

  close LOG;

} #end machine for()

sub match_regex
{
  my $prt = $File::Find::name;
  $prt =~ tr/\//\\/;
  print "processing file: $prt\n";
  if ( ($_ =~ /\.mdf$/i) || ($_ =~ /\.ldf$/i) || ($_ =~ /\.sql$/i) || ($_ =~ /\.xml$/i) || ($_ =~ /\.log$/i) ||
       ($_ =~ /sqlsp.log/i) || ($_ =~ /setup.iss/i) )
  {
    my $path = $File::Find::name;

    #fix up path before calling report perms or it will bomb!
    $path =~ tr/\//\\/;

    #tell about it
    print LOG "$path" . "\n";
 }
}

#-----------------#
# Permissions Sub #
#-----------------#
sub ReportPerms
{
  my( $Path ) = @_;
  my( $Acct, @List );
  my( $Perm ) = new Win32::Perms( $Path );
  my( %PermList ) = ();
  my( $MaxAcctLength ) = 1;
  my( $iTotal );

  if( ! $Perm )
  {
    print LOG "Can not obtain permissions for '$Path'\n";
    return;
  };

  printf LOG ( "  Owner: %s\n  Group: %s\n",
               $Perm->Owner(),
               $Perm->Group() );

  $Perm->Get( \@List );
  foreach my $Acct ( @List )
  {
    next unless( defined $Acct->{Access} );
    my $PermMask = 0;
    my( $Mask, @M, @F );
    my( $DaclType );
    my $bAllowAccess = ( "Deny" ne $Acct->{Access} );
    my $String;
    my $Account;

    next if( $Acct->{Entry} ne "DACL" );

    if( "" eq $Acct->{Account} )
    {
      $Account = $Acct->{SID};
    }
    else
    {
      $Account = "$Acct->{Domain}\\" if( "" ne $Acct->{Domain} );
      $Account .= $Acct->{Account};
    }
    if( length( $Account ) > $MaxAcctLength )
    {
      $MaxAcctLength = length( $Account )
    }
    $iTotal++;
    DecodeMask( $Acct, \@M, \@F );
    foreach my $Mask ( @M )
    {
      next unless( defined $MAP{$Mask} );
      my $Mapping = $MAP{$Mask};
      my $Permission = $PERM{$Mapping};
      $PermMask |= 2**$Permission;
    }
    $DaclType = $Acct->{ObjectName};
    if( 2 == $Acct->{ObjectType} )
    {
      # We have either a file or directory. Therefore we need to
      # figure out if this DACL represents an object (file) or
      # a container (dir)...
      if( $Acct->{Flag} & DIR )
      {
        $DaclType = "Directory";
      }
      else
      {
        $DaclType = "File";
      }
    }
    if( ! defined $PermList{$Account}->{$DaclType} )
    {
      # Create the permission string array. The first element in the
      # array must be blank since all unhandled permissions will default
      # to that position (and we won't print it).
      my $TempHash = [
                       " ",
                       split( //, "-" x scalar( keys( %PERM ) ) )
                     ];
      $PermList{$Account}->{$DaclType} = $TempHash;

    }
    foreach $Mask ( keys( %PERM ) )
    {
      if( $PermMask & 2**$PERM{$Mask} )
      {
        $String = $PermList{$Account}->{$DaclType};
        # If we already have a denied permission then skip this step
        # since denied access overrides any explicitly allowed access
        if( $String->[$PERM{$Mask}] !~ /[a-z]/ )
        {
          my $TempMask = $Mask;
          $TempMask = lc $Mask if( 0 == $bAllowAccess );
          $String->[$PERM{$Mask}] = $TempMask ;
        }
      }
    }
  }

  if( ! $iTotal )
  {
    # There are no DACL entries therefore...
    print LOG "\t Everyone has full permissions.\n";
  }
  else
  {
    foreach my $Permission ( sort( keys( %PermList ) ) )
    {
      foreach my $DaclType ( sort( keys( %{$PermList{$Permission}} ) ) )
      {
        my $String = $PermList{$Permission}->{$DaclType};
        printf LOG ( "  % " . $MaxAcctLength . "s % -11s %s\n",
                     $Permission,
                     "($DaclType)",
                     join( '', @$String ) );
      }
    }
  }

} #end ReportPerms

#----------------#
# Add Connection #
#----------------#
sub AddShareConnection
{
 my($href,$drive) = @_;
 my($pass);
 my($user);

 #add connection
 $href->{"LocalName"} = $drive;
 if ( Win32::NetResource::AddConnection( \%$href, $pass, $user, 1) )
 {
  print "Successfully connected!\n";
  print "Go into 'My Computer' and you should see this drive mapped to '" . $drive . "'\n";
 }else
 {
   print "Couldn't connect --> perhaps that letter/drive is already mapped?\n";
 }
}

#-------#
# Usage #
#-------#
sub Usage
{
print "\n";
print <<'--Usage--';

Usage:
 cmd> opensh.pl [ -m Machine  | -l TextFile.txt | -i IP_Address(es) ]

       -m Machine........A single machine to scan for open
                         shares.
       -l TextFile.txt...A path to a text file containing a
                         a list of machines.  This list
                         must contain a machine on each line.
                         If a machine is prepended by a \\,
                         that's ok...it will be substituted.
                         Ideally this would be a text file
                         that matches the format of the
                         'net view' command.
       -i IP_Address.....An IP address or range of IPs to
                         scan. To specify a range enter it
                         in this format: 192.168.1.2-254.
                         This would scan 192.168.1.2 to
                         192.168.1.254.

 The script will create a text file for each machine
 scanned containing log details for open shares and
 interesting files matched against.

 Examples:

  cmd> opensh.pl -m GOP21452

      *Scan for all open shares on machine GOP21542

  cmd> opensh.pl -l Machines.txt

      *Scan for all open shares for machines specified
       in the Machines.txt file.

  cmd> opensh.pl -i 192.168.1.2-254
  
      *Scan all machines assigned IP addresses 
       192.168.1.2 thru 192.168.1.254
--Usage--
exit;
}