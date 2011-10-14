use Bison;

initfw();

override_global({verbose => 1});

chain('new', {name => 'my_new_chain', jump => 'drop'});

sub list_chains {
    my $i = 0;
    for (chain('list')) {
        $i++;
        print "$i: $_\n";
    }
}

list_chains();
        
bison_finish();
