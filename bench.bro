redef Site::local_nets = {
    192.168.0.0/16,         # Private IP space
};
@load local

@ifdef(TeamCymruMalwareHashRegistry::match_file_types)
    redef TeamCymruMalwareHashRegistry::match_file_types = /NONONO/;
@endif

@ifdef(MalwareHashRegistery::match_file_types)
    redef MalwareHashRegistery::match_file_types = /NONONO/;
@endif
