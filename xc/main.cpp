#include "xe_client.h"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <json/json.h>

extern "C"
{
#include <xen/api/xen_all.h>
}

struct args {
    std::string url;
    std::string username;
    std::string password;
    std::string storage_dir;
};

void dump_vm(const struct args& args)
{
    Xe_Client c(args.url, args.username, args.password);
    c.connect();
    c.scan_hosts();
    c.scan_vms();
    c.dump();
}

void dump_all(const struct args& args)
{
    Xe_Client c(args.url, args.username, args.password);
    c.connect();
    c.scan_hosts();
    c.scan_vms();
    c.scan_srs();
    c.write_to_json();
}

void backup_vm(const struct args& args, const std::string& vm_uuid)
{
    Xe_Client c(args.url, args.username, args.password);
    c.connect();
    // c.scan_hosts();
    // c.scan_vms();

    c.backup_vm(vm_uuid, args.storage_dir);
}

void backup_vm_diff(const struct args& args, const std::string& vm_uuid)
{
    Xe_Client c(args.url, args.username, args.password);
    c.connect();
    // c.scan_hosts();
    // c.scan_vms();

    c.backup_vm_diff(vm_uuid, args.storage_dir);
}

void restore_vm(const struct args& args,
                const std::string& sr_uuid,
                const std::string& set_id)
{
    Xe_Client c(args.url, args.username, args.password);
    c.connect();
    c.restore_vm(args.storage_dir, sr_uuid, set_id);
}

void dump_srs(const struct args& args)
{
    Xe_Client c(args.url, args.username, args.password);
    c.connect();
    c.scan_srs();
}

void dump_backupsets(const struct args& args)
{
    Xe_Client c(args.url, args.username, args.password);
    c.backupset_list();
}

void dump_host_networks(const struct args& args)
{
    Xe_Client c(args.url, args.username, args.password);
    c.connect();
    c.scan_networks();
}

void rm_backup_set(const struct args& args, const std::string& set_id)
{
    Xe_Client c(args.url, args.username, args.password);
    c.rm_backupset(args.storage_dir, set_id);
}

void usage()
{
    std::cout << "Usage: " << std::endl;
    std::cout << "   all: list all vms and hosts and srs" << std::endl;
    std::cout << "   vms: list hosts and vms" << std::endl;
    std::cout << "   backup <vm_uuid>: backup vm by uuid" << std::endl;
    std::cout << "   backup_diff <vm_uuid>: backup diff vm by uuid" << std::endl;
    std::cout << "   restore <set_id> <sr_uuid>: restore vm from set_id to sr_uuid" << std::endl;
    std::cout << "   srs: list storage repository" << std::endl;
    std::cout << "   networks: list network of host" << std::endl;
    std::cout << "   sets: list backupset" << std::endl;
    std::cout << "   rm <set_id>: remove backupset, if set_id is all, rm all" << std::endl;
}

bool parse_config(struct args& args)
{
    std::ifstream file("config.conf");
    Json::CharReaderBuilder reader;
    Json::Value root;
    JSONCPP_STRING errs;

    if (!Json::parseFromStream(reader, file, &root, &errs)) {
        std::cout << "Error parsing JSON: " << errs << std::endl;
        file.close();
        return false;
    }
    file.close();

    args.url = root["xenserver"]["host"].asString();
    args.username = root["xenserver"]["username"].asString();
    args.password = root["xenserver"]["password"].asString();
    args.storage_dir = root["storage"]["dir"].asString();
    std::cout << "=================== args ======================" << std::endl;
    std::cout << "url: " << args.url << std::endl;
    std::cout << "username: " << args.username << std::endl;
    std::cout << "password: " << args.password << std::endl;
    std::cout << "storage_dir: " << args.storage_dir << std::endl;
    std::cout << "===============================================" << std::endl;
    std::cout << std::endl;
    return true;
}

int main(int argc, char*argv[])
{
    struct args args;
    if (!parse_config(args)) {
        std::cout << "Failed to parse config file" << std::endl;
        return 0;
    }

    if (!std::filesystem::is_directory(args.storage_dir)) {
        std::filesystem::create_directory(args.storage_dir);
    }

    for (int i = 0; i < argc; i++) {
        if (i == 1) {
            if (strcmp(argv[i], "vms") == 0) {
                dump_vm(args);
                return 0;
            } else if (strcmp(argv[i], "backup") == 0) {
                if (argc == 3) {
                    backup_vm(args, argv[2]);
                    return 0;
                }
            } else if (strcmp(argv[i], "backup_diff") == 0) {
                if (argc == 3) {
                    backup_vm_diff(args, argv[2]);
                    return 0;
                }
            } else if (strcmp(argv[i], "srs") == 0) {
                dump_srs(args);
                return 0;
            } else if (strcmp(argv[i], "network") == 0) {
                dump_host_networks(args);
                return 0;
            } else if (strcmp(argv[i], "sets") == 0) {
                dump_backupsets(args);
                return 0;
            } else if (strcmp(argv[i], "all") == 0) {
                dump_all(args);
                return 0;
            } else if (strcmp(argv[i], "restore") == 0) {
                if (argc == 4) {
                    restore_vm(args, argv[2], argv[3]);
                    return 0;
                }
            } else if (strcmp(argv[i], "rm") == 0) {
                if (argc == 3) {
                    rm_backup_set(args, argv[2]);
                    return 0;
                }
            }
        }
    }

    usage();
    return 0;
}
