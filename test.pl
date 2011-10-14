use Bison;

override_global({verbose => 1});
        
chain ('new',{
    name    => 'zerowall',
    jump    => 'drop',
});

log_setup ('zerowall', { time => 10, duration => 'minute', prefix => 'ZeroWall' });

bison_finish();
