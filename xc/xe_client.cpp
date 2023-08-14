#include "xe_client.h"
#include <curl/curl.h>
#include <libxml/parser.h>
#include <iostream>
#include <fstream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <json/json.h>
#include <thread>
#include <sys/stat.h>

#define BACKUP_SET_CONF "backup_set.json"
#define VM_META_CONF "vm_meta.json"
typedef struct
{
    xen_result_func func;
    void *handle;
} xen_comms;

const char *VM_POWER_STATE[] = {
    "VM_POWER_STATE_HALTED",
    "VM_POWER_STATE_PAUSED",
    "VM_POWER_STATE_RUNNING",
    "VM_POWER_STATE_SUSPENDED",
    "VM_POWER_STATE_UNDEFINED"
};

size_t writefile(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t totalSize = size * nmemb;
    std::ofstream* file = static_cast<std::ofstream*>(userp);
    if (file && file->is_open()) {
        file->write(static_cast<char*>(contents), totalSize);
        return totalSize;
    }
    return 0;
}

size_t readfile(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t totalSize = size * nmemb;
    std::ifstream* file = static_cast<std::ifstream*>(userp);
    if (file && file->is_open()) {
        file->read(static_cast<char*>(contents), totalSize);
        return totalSize;
    }
    return 0;
}

static size_t write_func(void *ptr, size_t size, size_t nmemb, xen_comms *comms)
{
    size_t n = size * nmemb;
    return comms->func(ptr, n, comms->handle) ? n : 0;
}

static int call_func(const void *data, size_t len, void *user_handle,
                     void *result_handle, xen_result_func result_func)
{
    (void) user_handle;
    CURL *curl = curl_easy_init();
    if (!curl)
        return -1;

    xen_comms comms = {
        .func = result_func,
        .handle = result_handle
    };

    char* url = (char*)user_handle;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &write_func);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &comms);
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, len);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);

    CURLcode result = curl_easy_perform(curl);

    curl_easy_cleanup(curl);

    return result;
}

std::string current_time_str()
{
    auto now = std::chrono::system_clock::now();
    std::time_t timestamp = std::chrono::system_clock::to_time_t(now);
    std::tm local_time = *std::localtime(&timestamp);
    char buffer[80];
    std::strftime(buffer, 80, "%Y%m%d%H%M%S", &local_time);
    return std::string(buffer);
}

Xe_Client::Xe_Client(std::string host, std::string user, std::string pass)
    : host_(std::move(host)), user_(std::move(user)), pass_(std::move(pass))
{
    xmlInitParser();
    xen_init();
    curl_global_init(CURL_GLOBAL_ALL);
}

Xe_Client::~Xe_Client()
{
}

bool Xe_Client::connect()
{
    session_ = xen_session_login_with_password(
        call_func, (void*)host_.c_str(), user_.c_str(), pass_.c_str(),
        xen_api_latest_version);

    return session_->ok;
}

bool Xe_Client::scan_hosts()
{
    xen_host_set *hosts = nullptr;
    if (!xen_host_get_all(session_, &hosts))
        return false;

    for (int i = 0; i < hosts->size; ++i) {
        xen_host host = hosts->contents[i];
        xen_host_record *host_record = nullptr;
        if (!xen_host_get_record(session_, &host_record, host)) {
            xen_host_set_free(hosts);
            return false;
        }

        struct host& h = hosts_[host_record->uuid];
        h.uuid = host_record->uuid;
        h.address = host_record->address;
        h.host = host_record->hostname;
    }

    xen_host_set_free(hosts);
    return true;
}

bool Xe_Client::scan_vms()
{
    struct xen_vm_set *vms = nullptr;
    if (!xen_vm_get_all(session_, &vms))
        return false;

    for (int i = 0; i < vms->size; ++i) {
        xen_vm vm = vms->contents[i];
        struct vm v;
        if (!get_vm(vm, v))
            continue;

        struct host& h = hosts_[v.host_uuid];
        h.vms.push_back(std::move(v));
    }

    xen_vm_set_free(vms);
    return true;
}

bool Xe_Client::get_vm(xen_vm x_vm, struct vm& v, bool snapshot)
{
    xen_vm_record *vm_record = nullptr;
    if (!xen_vm_get_record(session_, &vm_record, x_vm)) {
        std::cout << "Failed to get vm record" << std::endl;
        return false;
    }

    if (!snapshot) {
        if (vm_record->is_a_template || vm_record->is_control_domain || vm_record->is_a_snapshot) {
            std::cout << "Skipping template or control domain" << std::endl;
            xen_vm_record_free(vm_record);
            return false;
        }
    }

    for (int m = 0; m < vm_record->allowed_operations->size; m++) {
        v.allowed_operations.push_back(vm_record->allowed_operations->contents[m]);
    }

    v.uuid = vm_record->uuid;
    v.power_state = (int)vm_record->power_state;
    v.name_label = vm_record->name_label;
    v.name_description = vm_record->name_description;
    v.user_version = vm_record->user_version;
    v.is_a_template = vm_record->is_a_template;
    v.memory_overhead = vm_record->memory_overhead;
    v.memory_target = vm_record->memory_target;
    v.memory_static_max = vm_record->memory_static_max;
    v.memory_dynamic_max = vm_record->memory_dynamic_max;
    v.memory_dynamic_min = vm_record->memory_dynamic_min;
    v.memory_static_min = vm_record->memory_static_min;

    for (int m = 0; m < vm_record->vcpus_params->size; m++) {
        xen_string_string_map_contents pair = vm_record->vcpus_params->contents[m];
        v.vcpus_params[pair.key] = pair.val;
    }
    v.vcpus_max = vm_record->vcpus_max;
    v.vcpus_at_startup = vm_record->vcpus_at_startup;
    v.actions_after_shutdown = (int)vm_record->actions_after_shutdown;
    v.actions_after_reboot = (int)vm_record->actions_after_reboot;
    v.actions_after_crash = (int)vm_record->actions_after_crash;

    if (!get_vbds(v, vm_record)) {
        xen_vm_record_free(vm_record);
        return false;
    }

    if (!snapshot) {
        char* host_uuid = nullptr;
        if (!xen_host_get_uuid(session_, &host_uuid, vm_record->resident_on->u.handle)) {
            std::cout << "Failed to get host uuid" << std::endl;
            xen_vm_record_free(vm_record);
            return false;
        } else {
            v.host_uuid = host_uuid;
            free(host_uuid);
        }
    }

    return true;
}

bool Xe_Client::get_vbds(struct vm &v, xen_vm_record *vm_record)
{
    for (int m = 0; m < vm_record->vbds->size; m++) {
        xen_vbd_record_opt *opt = vm_record->vbds->contents[m];
        if (opt->is_record) {
            continue;
        }

        xen_vbd_record *vrec = nullptr;
        if (!xen_vbd_get_record(session_, &vrec, opt->u.handle)) {
            return false;
        } else {
            if (vrec->type != XEN_VBD_TYPE_DISK) {
                continue;
            }

            struct vbd vb;
            vb.uuid = vrec->uuid;
            vb.bootable = vrec->bootable;
            if (!vrec->vdi) {
                v.vbds.push_back(std::move(vb));
                xen_vbd_record_free(vrec);
                continue;
            }
            // scan vdi
            xen_vdi_record *vdi_record = nullptr;
            if (xen_vdi_get_record(session_, &vdi_record, vrec->vdi->u.handle)) {
                vb.vdi.vdi = (char*)vrec->vdi->u.handle;
                vb.vdi.uuid = vdi_record->uuid;
                vb.vdi.name_label = vdi_record->name_label;
                vb.vdi.name_description = vdi_record->name_description;
                vb.vdi.virtual_size = vdi_record->virtual_size;
                vb.vdi.physical_utilisation = vdi_record->physical_utilisation;
                vb.vdi.type = vdi_record->type;
                vb.vdi.sharable = vdi_record->sharable;
                vb.vdi.read_only = vdi_record->read_only;
                xen_vdi_record_free(vdi_record);
            }

            v.vbds.push_back(std::move(vb));
            xen_vbd_record_free(vrec);
        }
    }

    return true;
}

bool Xe_Client::dump()
{
    for (const auto& h : hosts_) {
        std::cout << "host: " << h.second.uuid << std::endl;
        std::cout << "  address: " << h.second.address << std::endl;
        std::cout << "  hostname: " << h.second.host << std::endl;
        for (const auto& v: h.second.vms) {
            std::cout << "    vm: " << v.uuid << std::endl;

            std::cout << "      allowed_operation: ";
            for (const auto& m : v.allowed_operations)
                std::cout << m << ",";
            std::cout << std::endl;

            std::cout << "      power_state: " << v.power_state << std::endl;
            std::cout << "      name: " << v.name_label << std::endl;
            std::cout << "      name_description: " << v.name_description << std::endl;
            std::cout << "      user_version: " << v.user_version << std::endl;
            std::cout << "      is_a_template: " << v.is_a_template << std::endl;

            std::cout << "      memory_overhead: " << v.memory_overhead << std::endl;
            std::cout << "      memory_target: " << v.memory_target << std::endl;
            std::cout << "      memory_static_max: " << v.memory_static_max << std::endl;
            std::cout << "      memory_dynamic_max: " << v.memory_dynamic_max << std::endl;
            std::cout << "      memory_dynamic_min: " << v.memory_dynamic_min << std::endl;
            std::cout << "      memory_static_min: " << v.memory_static_min << std::endl;

            for (const auto&m : v.vcpus_params)
                std::cout << "      vcpus_params: " << m.first << "=" << m.second << std::endl;

            std::cout << "      vcpus_max: " << v.vcpus_max << std::endl;
            std::cout << "      vcpus_at_startup: " << v.vcpus_at_startup << std::endl;
            std::cout << "      actions_after_shutdown: " << v.actions_after_shutdown << std::endl;
            std::cout << "      actions_after_reboot: " << v.actions_after_reboot << std::endl;
            std::cout << "      actions_after_crash: " << v.actions_after_crash << std::endl;

            for (const auto& vb : v.vbds) {
                std::cout << "      vbd: " << vb.uuid << std::endl;
                std::cout << "      bootable: " << vb.bootable << std::endl;
                std::cout << "        vdi: " << vb.vdi.uuid << std::endl;
                std::cout << "          name_label: " << vb.vdi.name_label << std::endl;
                std::cout << "          name_description: " << vb.vdi.name_description << std::endl;
                std::cout << "          virtual_size: " << vb.vdi.virtual_size << std::endl;
                std::cout << "          physical_utilisation: " << vb.vdi.physical_utilisation << std::endl;
                std::cout << "          type: " << vb.vdi.type << std::endl;
                std::cout << "          sharable: " << vb.vdi.sharable << std::endl;
                std::cout << "          read_only: " << vb.vdi.read_only << std::endl;
            }
        }
    }

    return true;
}

bool Xe_Client::write_to_json()
{
    Json::Value root;
    Json::Value hosts(Json::arrayValue);
    for (const auto& h : hosts_) {
        Json::Value host;
        host["uuid"] = h.second.uuid;
        host["address"] = h.second.address;
        host["hostname"] = h.second.host;

        Json::Value vms(Json::arrayValue);
        for (const auto& v: h.second.vms) {
             Json::Value vm;
             vm["uuid"] = v.uuid;

             Json::Value allowed_operations(Json::arrayValue);
             for (const auto& m : v.allowed_operations) {
                 allowed_operations.append(m);
             }
             vm["allowed_operations"] = allowed_operations;

             vm["name"] = v.name_label;
             vm["name_description"] = v.name_description;
             vm["power_state"] = v.power_state;
             vm["user_version"] = v.user_version;
             vm["is_a_template"] = v.is_a_template;
             vm["memory_overhead"] = v.memory_overhead;
             vm["memory_target"] = v.memory_target;
             vm["memory_static_max"] = v.memory_static_max;
             vm["memory_dynamic_max"] = v.memory_dynamic_max;
             vm["memory_dynamic_min"] = v.memory_dynamic_min;
             vm["memory_static_min"] = v.memory_static_min;
             vm["vcpus_max"] = v.vcpus_max;
             vm["vcpus_at_startup"] = v.vcpus_at_startup;
             vm["actions_after_shutdown"] = v.actions_after_shutdown;
             vm["actions_after_reboot"] = v.actions_after_reboot;
             vm["actions_after_crash"] = v.actions_after_crash;

            Json::Value vdbs(Json::arrayValue);
             for (const auto& vb : v.vbds) {
                Json::Value vdb;
                Json::Value vdi;
                vdb["uuid"] = vb.uuid;

                vdi["uuid"] = vb.vdi.uuid;
                vdi["name_label"] = vb.vdi.name_label;
                vdi["name_description"] = vb.vdi.name_description;
                vdi["virtual_size"] = vb.vdi.virtual_size;
                vdi["physical_utilisation"] = vb.vdi.physical_utilisation;
                vdi["type"] = vb.vdi.type;
                vdi["sharable"] = vb.vdi.sharable;
                vdi["read_only"] = vb.vdi.read_only;
                vdb["vdi"] = vdi;
                vdbs.append(vdb);
             }
             vm["vbds"] = vdbs;
             vms.append(vm);
        }

        host["vms"] = vms;
        hosts.append(host);
    }
    root["hosts"] = hosts;

    Json::Value srs(Json::arrayValue);
    for (const auto &s : srs_) {
        Json::Value sr;
        sr["uuid"] = s.uuid;
        sr["name_label"] = s.name_label;
        sr["name_description"] = s.name_description;
        sr["physical_size"] = s.physical_size;
        sr["physical_utilisation"] = s.physical_utilisation;
        sr["type"] = s.type;
        srs.append(sr);
    }
    root["srs"] = srs;

    std::ofstream outputFile("meta.json");
    outputFile << root;
    outputFile.close();

    return true;
}

bool Xe_Client::add_backup_set(const struct backup_set &bset)
{
    std::ifstream input_file(BACKUP_SET_CONF);
    Json::CharReaderBuilder reader;
    Json::Value root;
    JSONCPP_STRING errs;

    if (!Json::parseFromStream(reader, input_file, &root, &errs)) {
        std::cout << "Error parsing JSON: " << errs << std::endl;
        input_file.close();

        Json::Value bs(Json::arrayValue);
        Json::Value s;
        s["date"] = bset.date;
        s["set_id"] = bset.vm_name;
        s["vm_uuid"] = bset.vm_uuid;
        s["type"] = bset.type;

        bs.append(s);
        root["sets"] = bs;

        std::ofstream output_file(BACKUP_SET_CONF);
        output_file << root;
        output_file.close();

        return true;
    }
    input_file.close();

    Json::Value s;
    s["date"] = bset.date;
    s["vm_name"] = bset.vm_name;
    s["vm_uuid"] = bset.vm_uuid;
    s["type"] = bset.type;
    root["sets"].append(s);

    std::ofstream output_file(BACKUP_SET_CONF);
    output_file << root;
    output_file.close();

    return true;
}

bool Xe_Client::add_vm_meta(const struct backup_set &bset)
{
    Json::Value root;
    root["date"] = bset.date;
    root["vm_name"] = bset.vm_name;
    root["vm_uuid"] = bset.vm_uuid;
    root["type"] = bset.type;

    Json::Value vm;
    vm["uuid"] = bset.vm.uuid;
    vm["name_label"] = bset.vm.name_label;
    vm["name_description"] = bset.vm.name_description;

    Json::Value vbds(Json::arrayValue);
    for (const auto& b : bset.vm.vbds) {
        Json::Value vbd;
        vbd["uuid"] = b.uuid;
        vbd["bootable"] = b.bootable;

        Json::Value vdi;
        vdi["uuid"] = b.vdi.uuid;
        vdi["name_label"] = b.vdi.name_label;
        vdi["name_description"] = b.vdi.name_description;
        vdi["virtual_size"] = b.vdi.virtual_size;
        vdi["physical_utilisation"] = b.vdi.physical_utilisation;
        vdi["type"] = b.vdi.type;
        vdi["sharable"] = b.vdi.sharable;
        vdi["read_only"] = b.vdi.read_only;
        vbd["vdi"] = vdi;

        vbds.append(vbd);
    }

    vm["vbds"] = vbds;
    root["vm"] = vm;

    std::string file = bset.vm_name + "/" + VM_META_CONF;
    std::ofstream output_file(file);
    output_file << root;
    output_file.close();

    return true;
}

bool Xe_Client::backup_vm(const std::string &vm_uuid, const std::string &backup_dir)
{
    struct backup_set bt;
    if (!backup_vm_i(vm_uuid, backup_dir, bt)) {
        std::cout << "Failed to backup vm: " << vm_uuid << std::endl;
        return false;
    }

    if (!add_backup_set(bt)) {
        std::cout << "Failed to add backup set: " << vm_uuid << std::endl;
        return false;
    }

    if (!add_vm_meta(bt)) {
        std::cout << "Failed to add vm meta: " << vm_uuid << std::endl;
        return false;
    }

    return true;
}

bool Xe_Client::backup_vm_i(const std::string &vm_uuid, const std::string &backup_dir, struct backup_set &bt)
{
    xen_vm backup_vm = nullptr;
    if (!xen_vm_get_by_uuid(session_, &backup_vm, (char *)vm_uuid.c_str())) {
        std::cout << "Failed to get vm by uuid: " << vm_uuid << std::endl;
        return false;
    }

    bool ret = true;

    std::string cur_date = current_time_str();
    bt.date = cur_date;
    bt.type = "full";
    std::string snap_name = vm_uuid + "_" + cur_date;
    std::cout << "snap_name: " << snap_name << std::endl;
    bt.vm_name = snap_name;
    bt.vm_uuid = vm_uuid;

    xen_vbd_set* vbd_set = nullptr;
    // do snapshot
    xen_vm snap_handle = nullptr;
    if (!xen_vm_snapshot(session_, &snap_handle,
                         backup_vm, const_cast<char *>(snap_name.c_str()))) {
        std::cout << "Failed to snapshot vm: " << vm_uuid << std::endl;
        return false;
    }
    xen_vm_free(backup_vm);

    struct vm v;
    if (!get_vm(snap_handle, v, true)) {
        std::cout << "Failed to get vm: " << vm_uuid << std::endl;
        return false;
    }

    mkdir(snap_name.c_str(), 0777);
    for (const auto &vb : v.vbds) {
        xen_task task = nullptr;
        std::string task_name("export_raw_vdi");
        if (!xen_task_create(session_, &task, (char*)task_name.c_str(),
                                const_cast<char *>("task"))) {
            std::cout << "Failed to create task" << std::endl;
            xen_vbd_set_free(vbd_set);
            return false;
        }

        std::string file = snap_name + "/" + vb.vdi.uuid + ".vhd";
        std::string url = export_url(task, vb.vdi.vdi);
        std::thread t(&Xe_Client::http_download, this, url, file);
        progress(task);
        t.join();
        xen_task_free(task);
    }

    bt.vm = std::move(v);

    // // get vdb by snapshot
    // if (!xen_vm_get_vbds(session_, &vbd_set, snap_handle)) {
    //     std::cout << "Failed to get vbd set by vm: " << vm_uuid << std::endl;
    //     xen_vm_free(snap_handle);
    //     return false;
    // }
    // xen_vm_free(snap_handle);

    // if (!vbd_set) {
    //     std::cout << "vbd set is null" << std::endl;
    //     return false;
    // }

    // for (int i = 0; i < vbd_set->size; i++) {
    //     struct vbd vb;
    //     if (!vbd_set->contents[i]) {
    //         continue;
    //     }

    //     enum xen_vbd_type result_vbd_type = XEN_VBD_TYPE_UNDEFINED;
    //     if (!xen_vbd_get_type(session_, &result_vbd_type, vbd_set->contents[i])) {
    //         std::cout << "Failed to get vbd type" << std::endl;
    //         xen_vbd_set_free(vbd_set);
    //         return false;
    //     }

    //     if (result_vbd_type != XEN_VBD_TYPE_DISK) {
    //         continue;
    //     }

    //     // get vdi by vbd
    //     xen_vdi vdi_of_vbd = nullptr;
    //     if (!xen_vbd_get_vdi(session_, &vdi_of_vbd, vbd_set->contents[i])) {
    //         std::cout << "Failed to get vdi by vbd" << std::endl;
    //         xen_vbd_set_free(vbd_set);
    //         return false;
    //     }

    //     if (!vdi_of_vbd) {
    //         std::cout << "vdi of vbd is null" << std::endl;
    //         xen_vbd_set_free(vbd_set);
    //         return false;
    //     }

    //     if (strcmp("OpaqueRef:NULL", (char *)vdi_of_vbd)) {
    //         char* vdi_uuid = nullptr;
    //         if (!xen_vdi_get_uuid(session_, &vdi_uuid, vdi_of_vbd)) {
    //             std::cout << "Failed to get vdi uuid" << std::endl;
    //             xen_vbd_set_free(vbd_set);
    //             return false;
    //         }

    //         if (!vdi_uuid) {
    //             std::cout << "vdi uuid is null" << std::endl;
    //             xen_vbd_set_free(vbd_set);
    //             return false;
    //         }
    //         vb.vdi.uuid = vdi_uuid;

    //         xen_vdi_record *vdi_record = nullptr;
    //         if (xen_vdi_get_record(session_, &vdi_record, vdi_of_vbd)) {
    //             vb.vdi.uuid = vdi_record->uuid;
    //             vb.vdi.name_label = vdi_record->name_label;
    //             vb.vdi.name_description = vdi_record->name_description;
    //             vb.vdi.virtual_size = vdi_record->virtual_size;
    //             vb.vdi.physical_utilisation = vdi_record->physical_utilisation;
    //             vb.vdi.type = vdi_record->type;
    //             vb.vdi.sharable = vdi_record->sharable;
    //             vb.vdi.read_only = vdi_record->read_only;
    //             xen_vdi_record_free(vdi_record);
    //         } else {
    //             std::cout << "Failed to get vdi record" << std::endl;
    //         }
    //         bt.vm.vbds.push_back(vb);

    //         xen_task task = nullptr;
    //         std::string task_name("export_raw_vdi");
    //         if (!xen_task_create(session_, &task, (char*)task_name.c_str(),
    //                              const_cast<char *>("task"))) {
    //             std::cout << "Failed to create task" << std::endl;
    //             xen_vbd_set_free(vbd_set);
    //             return false;
    //         }

    //         mkdir(snap_name.c_str(), 0777);
    //         std::string file = snap_name + "/" + vdi_uuid + ".vhd";
    //         std::string url = export_url(task, vdi_of_vbd);
    //         std::thread t(&Xe_Client::http_download, this, url, file);
    //         progress(task);
    //         t.join();
    //         free(vdi_uuid);
    //     }
    // }

    return true;
}

void Xe_Client::http_download(const std::string &url, const std::string &file)
{
    std::cout << "start to http download" << std::endl;
    CURL *curl =NULL;
    CURLcode res;
    long http_code;
    std::ofstream output_file(file, std::ios::binary);

    curl = curl_easy_init();

    if (curl){
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefile);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &output_file);
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
        //curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
        res = curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        curl_easy_cleanup(curl);
        output_file.close();
    }
}

void Xe_Client::http_upload(const std::string &url, const std::string &file)
{
    std::cout << "start to http download" << std::endl;
    CURL *curl =NULL;
    CURLcode res;
    long http_code;
    std::ifstream upload_file(file, std::ios::binary);
    if (!upload_file.is_open()) {
        std::cout << "Failed to open file: " << file << std::endl;
        return;
    }

    curl = curl_easy_init();

    if (curl){
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(curl, CURLOPT_PUT, 1L);
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, readfile);
        curl_easy_setopt(curl, CURLOPT_READDATA, &upload_file);
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

        struct stat file_info;
        stat(file.c_str(), &file_info);
        curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE,
                         (curl_off_t)file_info.st_size);
        res = curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        curl_easy_cleanup(curl);
    }

    upload_file.close();

    return;
}

void Xe_Client::progress(xen_task task)
{
    xen_task_status_type task_status;
    xen_task_get_status(session_, &task_status, task);
    double progress = 0;
    while (XEN_TASK_STATUS_TYPE_PENDING == task_status) {
        if (progress > 0.95) {
            break;
        }

        xen_task_get_progress(session_, &progress, task);
        std::cout << "progress: " << progress << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }

    return;
}

std::string Xe_Client::export_url(xen_task task, const std::string& vdi)
{
    std::string url = host_;
    url.append("/export_raw_vdi?session_id=");
    url.append(session_->session_id);
    url.append("&task_id=");
    url.append((char *)task);
    url.append("&vdi=");
    url.append(vdi);
    url.append("&format=vhd");

    std::cout << "export_url: " << url << std::endl;
    return url;
}

std::string Xe_Client::import_url(xen_task task, xen_vdi vdi)
{
    std::string url = host_;
    url.append("/import_raw_vdi?session_id=");
    url.append(session_->session_id);
    url.append("&task_id=");
    url.append((char *)task);
    url.append("&vdi=");
    url.append((char *)vdi);
    url.append("&format=vhd");

    std::cout << "import_url: " << url << std::endl;
    return url;
}

bool Xe_Client::scan_srs()
{
    xen_sr_set* sr_set = nullptr;
    if (!xen_sr_get_all(session_, &sr_set)) {
        std::cout << "Failed to get sr set" << std::endl;
        return false;
    }

    if (!sr_set) {
        std::cout << "sr set is null" << std::endl;
        return false;
    }

    bool ret = true;
    std::cout << "============ storage repository ============" << std::endl;
    for (int i = 0; i < sr_set->size; i++) {
        if (!sr_set->contents[i]) {
            continue;
        }

        xen_sr sr = sr_set->contents[i];
        xen_sr_record* sr_record = nullptr;
        if (!xen_sr_get_record(session_, &sr_record, sr)) {
            std::cout << "Failed to get sr record" << std::endl;
            ret = false;
            goto out;
        }

        if (!sr_record) {
            std::cout << "sr record is null" << std::endl;
            ret = false;
            goto out;
        }

        if (strcmp(sr_record->type, "iso") == 0 || strcmp(sr_record->type, "udev") == 0) {
            xen_sr_record_free(sr_record);
            continue;
        }

        struct sr s {
            sr_record->uuid,
            sr_record->name_label,
            sr_record->name_description,
            sr_record->type,
            sr_record->physical_size,
            sr_record->physical_utilisation
        };

        std::cout << "uuid: " << s.uuid << std::endl;
        std::cout << "  name_label: " << s.name_label << std::endl;
        std::cout << "  name_description: " << s.name_description << std::endl;
        std::cout << "  type: " << s.type << std::endl;
        std::cout << "  physical_size: " << s.physical_size << std::endl;
        srs_.emplace_back(std::move(s));
        xen_sr_record_free(sr_record);
    }
    std::cout << "============================================" << std::endl;
out:
    if (sr_set) {
        xen_sr_set_free(sr_set);
    }

    return true;
}

bool Xe_Client::restore_vm(const std::string& set_id, const std::string& sr_uuid)
{
    struct vm v;
    std::string meta_file = set_id + "/" + VM_META_CONF;
    if (!load_vm_meta(meta_file, v)) {
        std::cout << "Failed to load vm meta from " << meta_file << std::endl;
        return false;
    }

    if (!restore_vm_i(set_id, sr_uuid, v)) {
        std::cout << "Failed to restore vm " << v.name_label << std::endl;
        return false;
    }

    return true;
}

bool Xe_Client::backupset_list()
{
    std::ifstream file(BACKUP_SET_CONF);
    Json::CharReaderBuilder reader;
    Json::Value root;
    JSONCPP_STRING errs;

    if (!Json::parseFromStream(reader, file, &root, &errs)) {
        std::cout << "Failed to load backupset list " << BACKUP_SET_CONF << ", err: " << errs << std::endl;
        file.close();
        return false;
    }
    file.close();

    std::cout << "============ backup sets ============" << std::endl;
    for (const auto& b : root["sets"]) {
        std::cout << "  set_id: " << b["set_id"].asString() << std::endl;
    }
    std::cout << "=====================================" << std::endl;
    return true;
}

bool Xe_Client::load_vm_meta(const std::string& file, struct vm &vm)
{
    std::ifstream input_file(file);
    Json::CharReaderBuilder reader;
    Json::Value root;
    JSONCPP_STRING errs;

    if (!Json::parseFromStream(reader, input_file, &root, &errs)) {
        std::cout << "Failed to load vm meta from " << file << ", err: " << errs << std::endl;
        input_file.close();
        return false;
    }

    vm.uuid = root["vm"]["uuid"].asString();
    vm.name_label = root["vm"]["name_label"].asString();
    vm.name_description = root["vm"]["name_description"].asString();

    for (const auto& vbd : root["vm"]["vbds"]) {
        struct vbd vb;
        vb.uuid = vbd["uuid"].asString();
        vb.bootable = vbd["bootable"].asBool();
        vb.vdi.uuid = vbd["vdi"]["uuid"].asString();
        vb.vdi.name_label = vbd["vdi"]["name_label"].asString();
        vb.vdi.name_description = vbd["vdi"]["name_description"].asString();
        vb.vdi.physical_utilisation = vbd["vdi"]["physical_utilisation"].asInt64();
        vb.vdi.virtual_size = vbd["vdi"]["virtual_size"].asInt64();
        vb.vdi.type = vbd["vdi"]["type"].asInt();
        vb.vdi.sharable = vbd["vdi"]["sharable"].asBool();
        vb.vdi.read_only = vbd["vdi"]["read_only"].asBool();

        vm.vbds.emplace_back(std::move(vb));
    }

    return true;
}

bool Xe_Client::create_new_vm(std::string& vm_uuid)
{
    std::string temp = "CentOS 7";
    struct xen_vm_set *vms = nullptr;
    if (!xen_vm_get_all(session_, &vms))
        return false;

    xen_vm vm = nullptr;
    bool found = false;

    for (int i = 0; i < vms->size; ++i) {
        vm = vms->contents[i];
        xen_vm_record *vm_record = nullptr;
        if (!xen_vm_get_record(session_, &vm_record, vm)) {
            xen_vm_set_free(vms);
            return false;
        }

        if (!vm_record->is_a_template) {
            xen_vm_record_free(vm_record);
            continue;
        }

        if (strcmp(vm_record->name_label, temp.c_str()) == 0) {
            xen_vm_record_free(vm_record);
            found = true;
            break;
        }

        xen_vm_record_free(vm_record);
    }

    if (!found) {
        std::cout << "Failed to find template " << temp << std::endl;
        xen_vm_set_free(vms);
        return false;
    }

    xen_vm new_vm = nullptr;
    std::cout << "begin to clone vm" << std::endl;
    if (!xen_vm_clone(session_, &new_vm, vm, (char*)("test_centos"))) {
        std::cout << "Failed to clone vm" << std::endl;
        xen_vm_set_free(vms);
        return false;
    }
    std::cout << "clone vm successful" << std::endl;
    if (!new_vm) {
        std::cout << "vm is null" << std::endl;
        xen_vm_set_free(vms);
        return false;
    }

    xen_vm_record *vm_record = nullptr;
    if (!xen_vm_get_record(session_, &vm_record, new_vm)) {
        xen_vm_record_free(vm_record);
        xen_vm_set_free(vms);
        return false;
    }

    vm_uuid = vm_record->uuid;
    xen_vm_record_free(vm_record);
    xen_vm_set_free(vms);

    return true;
}

bool Xe_Client::restore_vm_i(const std::string& set_id, const std::string& sr_uuid, const struct vm& v)
{
    std::string new_vm_uuid;
    if (!create_new_vm(new_vm_uuid)) {
        std::cout << "Failed to create new vm" << std::endl;
        return false;
    }

    enum xen_vbd_type vbd_type_disk = xen_vbd_type_from_string(session_, "Disk");

    for (const auto& vb : v.vbds) {
        // must in for loop,  sr will be free by xen_vdi_record_free
        xen_sr sr = nullptr;
        if (!xen_sr_get_by_uuid(session_, &sr, (char *)sr_uuid.c_str())) {
            std::cout << "Failed to get sr by " << sr_uuid  << std::endl;
            return false;
        }

        xen_sr_record_opt* sr_record_opt = xen_sr_record_opt_alloc();
        sr_record_opt->is_record = false;
        sr_record_opt->u.handle = sr;

        xen_string_string_map *other_config = xen_string_string_map_alloc(0);
        xen_vdi_record* vdi0_record = xen_vdi_record_alloc();
        vdi0_record->sr = sr_record_opt;
        // vdi0_record->virtual_size = (int64_t)10 * 1024 * 1024 * 1024;
        // vdi0_record->type = XEN_VDI_TYPE_SYSTEM;
        // vdi0_record->sharable = false;
        // vdi0_record->read_only = false;
        vdi0_record->virtual_size = vb.vdi.virtual_size;
        vdi0_record->type = (xen_vdi_type)vb.vdi.type;
        vdi0_record->sharable = vb.vdi.sharable;
        vdi0_record->read_only = vb.vdi.read_only;
        vdi0_record->other_config = other_config;

        xen_vbd vdi0 = nullptr;
        if (!xen_vdi_create(session_, &vdi0, vdi0_record)) {
            std::cout << "Failed to create vdi0" << std::endl;
            xen_vdi_record_free(vdi0_record);
            return false;
        }
        xen_vdi_record_free(vdi0_record);

        // must in for loop, xen_vm will be free by xen_vm_record_free every loop
        xen_vm new_vm2;
        if (!xen_vm_get_by_uuid(session_, &new_vm2, (char*)new_vm_uuid.c_str())) {
             xen_vdi_record_free(vdi0_record);
            std::cout << "Failed to get vm by " << new_vm_uuid << std::endl;
            return false;
        }

        char* device_str =nullptr;
        xen_vm_record_opt* vm_record_opt = xen_vm_record_opt_alloc();
        vm_record_opt->is_record = false;
        vm_record_opt->u.handle = new_vm2;

        xen_vdi_record_opt* vdi0_record_opt = xen_vdi_record_opt_alloc();
        vdi0_record_opt->is_record = false;
        vdi0_record_opt->u.handle = vdi0;

        device_str = (char*)malloc(5);
        strcpy(device_str, "xvda");

        xen_string_string_map* qos_algorithm_params = xen_string_string_map_alloc(0);
        xen_string_string_map* vbd_other_config = xen_string_string_map_alloc(0);
        xen_vbd_record *vbd0_record = xen_vbd_record_alloc();
        vbd0_record->vm = vm_record_opt;
        vbd0_record->vdi = vdi0_record_opt;
        vbd0_record->userdevice = device_str;
        vbd0_record->type = vbd_type_disk;
        vbd0_record->mode = XEN_VBD_MODE_RW;
        vbd0_record->qos_algorithm_params = qos_algorithm_params;
        vbd0_record->other_config = vbd_other_config;
        vbd0_record->bootable = true;

        xen_vdi vbd0 = nullptr;
        if (!xen_vbd_create(session_, &vbd0, vbd0_record)) {
            std::cout << "Failed to create vbd0" << std::endl;
            xen_vbd_record_free(vbd0_record);
            return false;
        }

        xen_task task = nullptr;
        std::string task_name("import_raw_vdi");
        if (!xen_task_create(session_, &task, (char*)task_name.c_str(),
                                const_cast<char *>("task"))) {
            std::cout << "Failed to create task" << std::endl;
            xen_vbd_record_free(vbd0_record);
            return false;
        }

        std::string url = import_url(task, vdi0);
        std::string file = set_id + "/" + vb.vdi.uuid + ".vhd";
        std::thread t(&Xe_Client::http_upload, this, url, file);
        progress(task);
        t.join();

        xen_vbd_record_free(vbd0_record);
    }

    xen_vm new_vm3;
    if (!xen_vm_get_by_uuid(session_, &new_vm3, (char*)new_vm_uuid.c_str())) {
        std::cout << "Failed to get vm by " << new_vm_uuid << std::endl;
        return false;
    }
    xen_vm_provision(session_, new_vm3);
    return true;
}
