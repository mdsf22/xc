## config.conf
```
{
    "xenserver" : {
        "host" : "http://172.16.2.162",
        "username" : "root",
        "password" : "123456",
    },

    "storage" : {
        "dir" : "./",
    }
}

```

## build
```
sh build.sh
```


## run
```
Usage:
   all: list all vms and hosts and srs
   vms: list hosts and vms
   backup <vm_uuid>: backup vm by uuid
   restore <set_id> <sr_uuid>: restore vm by uuid
   srs: list storage repository
   sets: list backupset

```
