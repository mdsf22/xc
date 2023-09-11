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
#include <algorithm>
#include <sys/stat.h>
#include <filesystem>
#include <memory>

#define BACKUP_SET_CONF "backup_set.json"
#define VM_META_CONF "vm_meta.json"

#define BACKUP_TYPE_FULL "full"
#define BACKUP_TYPE_DIFF "diff"
typedef struct
{
    xen_result_func func;
    void *handle;
} xen_comms;

template<class T, class Deleter>
std::unique_ptr<T, Deleter> make_deleter(T* p, Deleter&& del)
{
    return std::unique_ptr<T, Deleter>(p, std::forward<Deleter>(del));
}

void print_error(xen_session *session)
{
    for (int i = 0; i < session->error_description_count; i++) {
        std::cout << session->error_description[i] << std::endl;
    }
}


void print_error(xen_session *session, char* format, ...)
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    std::cout << std::endl;
    va_end(args);
    print_error(session);
}

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
        std::cout << "== host " << h.host << std::endl;
        // scan pif
        if (host_record->pifs)
            scan_pif(host_record->pifs);
    }

    xen_host_set_free(hosts);
    return true;
}

bool Xe_Client::scan_pif(struct xen_pif_record_opt_set *pifs)
{
    for (int i = 0; i < pifs->size; ++i) {
        xen_pif_record_opt *opt = pifs->contents[i];
        if (opt->is_record) {
            continue;
        }

        xen_pif_record *pif_record = nullptr;
        if (!xen_pif_get_record(session_, &pif_record, opt->u.handle)) {
            return false;
        } else {
            // pif.IP = pif_record->IP;
            // pif.netmask = pif_record->netmask;
            // pif.gateway = pif_record->gateway;
            std::cout << "== ip " << pif_record->ip << std::endl;
            std::cout << "== device " << pif_record->device << std::endl;
        }
        xen_pif_record_free(pif_record);
    }
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

bool Xe_Client::get_vifs(xen_vm vm, std::vector<struct vif>& vifs)
{
    struct xen_vif_set *vif_set = nullptr;
    if (!xen_vm_get_vifs(session_, &vif_set, vm)) {
        print_error(session_, (char*)("Failed to get vifs"));
        return false;
    }

    auto s = make_deleter(vif_set, [](xen_vif_set* s) {
        xen_vif_set_free(s);
    });

    for (int i = 0; i < vif_set->size; ++i) {
        xen_vif_record *vif_record = nullptr;
        if (!xen_vif_get_record(session_, &vif_record, vif_set->contents[i])) {
            print_error(session_, (char*)("Failed to get vif record"));
            return false;
        }

        auto v = make_deleter(vif_record, [](xen_vif_record* vif) {
            xen_vif_record_free(vif);
        });

        xen_network_record *network_record = nullptr;
        if ((!xen_network_get_record(session_, &network_record, vif_record->network->u.handle))) {
            print_error(session_, (char*)("Failed to get network record"));
            return false;
        }

        auto n = make_deleter(network_record, [](xen_network_record* n) {
            xen_network_record_free(n);
        });

        struct vif vif {
            .uuid = vif_record->uuid,
            .device = vif_record->device,
            .mac = vif_record->mac,
            .mtu = vif_record->mtu
        };

        struct network network {
            .uuid = network_record->uuid,
            .name_label = network_record->name_label,
            .name_description = network_record->name_description,
            .mtu = network_record->mtu,
            .bridge = network_record->bridge,
        };

        vif.network = std::move(network);
        vifs.push_back(std::move(vif));
    }

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

    v.pv_bootloader = vm_record->pv_bootloader;
    v.pv_kernel = vm_record->pv_kernel;
    v.pv_ramdisk = vm_record->pv_ramdisk;
    v.pv_args = vm_record->pv_args;
    v.pv_bootloader_args = vm_record->pv_bootloader_args;
    v.pv_legacy_args = vm_record->pv_legacy_args;
    v.hvm_boot_policy = vm_record->hvm_boot_policy;

    for (int m = 0; m < vm_record->hvm_boot_params->size; m++) {
        xen_string_string_map_contents pair = vm_record->hvm_boot_params->contents[m];
        v.hvm_boot_params[pair.key] = pair.val;
    }

    v.hvm_shadow_multiplier = vm_record->hvm_shadow_multiplier;

    for (int m = 0; m < vm_record->platform->size; m++) {
        xen_string_string_map_contents pair = vm_record->platform->contents[m];
        v.platform[pair.key] = pair.val;
    }

    for (int m = 0; m < vm_record->other_config->size; m++) {
        xen_string_string_map_contents pair = vm_record->other_config->contents[m];
        v.other_config[pair.key] = pair.val;
    }

    if (!get_vbds(v, vm_record)) {
        xen_vm_record_free(vm_record);
        return false;
    }

    if (!get_vifs(x_vm, v.vifs)) {
        xen_vm_record_free(vm_record);
        return false;
    }

    if (!snapshot) {
        char* host_uuid = nullptr;
        if (!xen_host_get_uuid(session_, &host_uuid, vm_record->resident_on->u.handle)) {
            std::cout << "Failed to get host uuid" << std::endl;
            // must clear error, otherwise next call will fail
            xen_session_clear_error(session_);
        } else {
            v.host_uuid = host_uuid;
            free(host_uuid);
        }
    }

    xen_vm_record_free(vm_record);
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
            vb.device = vrec->device;
            vb.userdevice = vrec->userdevice;
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

void Xe_Client::dump_vm(const struct vm& v)
{
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

    std::cout << "      vcpus_params: " << std::endl;
    for (const auto&m : v.vcpus_params)
        std::cout << "        key: " << m.first << ", val: " << m.second << std::endl;

    std::cout << "      vcpus_max: " << v.vcpus_max << std::endl;
    std::cout << "      vcpus_at_startup: " << v.vcpus_at_startup << std::endl;
    std::cout << "      actions_after_shutdown: " << v.actions_after_shutdown << std::endl;
    std::cout << "      actions_after_reboot: " << v.actions_after_reboot << std::endl;
    std::cout << "      actions_after_crash: " << v.actions_after_crash << std::endl;
    std::cout << "      pv_bootloader: " << v.pv_bootloader << std::endl;
    std::cout << "      pv_kernel: " << v.pv_kernel << std::endl;
    std::cout << "      pv_ramdisk: " << v.pv_ramdisk << std::endl;
    std::cout << "      pv_args: " << v.pv_args << std::endl;
    std::cout << "      pv_bootloader_args: " << v.pv_bootloader_args << std::endl;
    std::cout << "      pv_legacy_args: " << v.pv_legacy_args << std::endl;
    std::cout << "      hvm_boot_policy: " << v.hvm_boot_policy << std::endl;
    std::cout << "      hvm_boot_params: " << std::endl;
    for (const auto&m : v.hvm_boot_params)
        std::cout << "        key: " << m.first << ", value" << m.second << std::endl;

    std::cout << "      hvm_shadow_multiplier: " << v.hvm_shadow_multiplier << std::endl;
    std::cout << "      platform: " << std::endl;
    for (const auto&m : v.platform)
        std::cout << "        key: " << m.first << ", value: " << m.second << std::endl;

    std::cout << "      other config: " << std::endl;
    for (const auto&m : v.other_config)
        std::cout << "        key: " << m.first << ", value" << m.second << std::endl;

    for (const auto& vb : v.vbds) {
        dump_vbd(vb);
    }

    for (const auto& vif : v.vifs) {
        dump_vif(vif);
    }
}

void Xe_Client::dump_vbd(const struct vbd& vb)
{
    std::cout << "      vbd: " << vb.uuid << std::endl;
    std::cout << "        device: " << vb.device << std::endl;
    std::cout << "        userdevice: " << vb.userdevice << std::endl;
    std::cout << "        bootable: " << vb.bootable << std::endl;
    std::cout << "          vdi: " << vb.vdi.uuid << std::endl;
    std::cout << "            vdi: " << vb.vdi.vdi << std::endl;
    std::cout << "            name_label: " << vb.vdi.name_label << std::endl;
    std::cout << "            name_description: " << vb.vdi.name_description << std::endl;
    std::cout << "            virtual_size: " << vb.vdi.virtual_size << std::endl;
    std::cout << "            physical_utilisation: " << vb.vdi.physical_utilisation << std::endl;
    std::cout << "            type: " << vb.vdi.type << std::endl;
    std::cout << "            sharable: " << vb.vdi.sharable << std::endl;
    std::cout << "            read_only: " << vb.vdi.read_only << std::endl;
}

void Xe_Client::dump_vif(const struct vif& vf)
{
    std::cout << "      vif: " << vf.uuid << std::endl;
    std::cout << "        device: " << vf.device << std::endl;
    std::cout << "        mac: " << vf.mac << std::endl;
    std::cout << "        mtu: " << vf.mtu << std::endl;
    std::cout << "          network: " << vf.network.uuid << std::endl;
    std::cout << "          name_label: " << vf.network.name_label << std::endl;
    std::cout << "          name_description: " << vf.network.name_description << std::endl;
    std::cout << "          mtu: " << vf.network.mtu << std::endl;
    std::cout << "          bridge: " << vf.network.bridge << std::endl;
}

bool Xe_Client::dump()
{
    for (const auto& h : hosts_) {
        std::cout << "host: " << h.second.uuid << std::endl;
        std::cout << "  address: " << h.second.address << std::endl;
        std::cout << "  hostname: " << h.second.host << std::endl;
        for (const auto& v: h.second.vms) {
            dump_vm(v);
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
    s["set_id"] = bset.vm_name;
    s["vm_uuid"] = bset.vm_uuid;
    s["type"] = bset.type;
    root["sets"].append(s);

    std::ofstream output_file(BACKUP_SET_CONF);
    output_file << root;
    output_file.close();

    return true;
}

bool Xe_Client::load_backup_sets(std::vector<struct backup_set>& bsets)
{
    std::ifstream input_file(BACKUP_SET_CONF);
    Json::CharReaderBuilder reader;
    Json::Value root;
    JSONCPP_STRING errs;

    if (!Json::parseFromStream(reader, input_file, &root, &errs)) {
        std::cout << "Error parsing JSON: " << errs << std::endl;
        input_file.close();
        return false;
    }

    input_file.close();

    for (const auto& s : root["sets"]) {
        struct backup_set bset {
            .vm_name = s["set_id"].asString(),
            .vm_uuid = s["vm_uuid"].asString(),
            .date = s["date"].asString(),
            .type = s["type"].asString()
        };

        bsets.emplace_back(std::move(bset));
    }

    return true;
}

bool Xe_Client::add_vm_meta(const std::string& dir, const struct backup_set &bset)
{
    Json::Value root;
    root["date"] = bset.date;
    root["vm_name"] = bset.vm_name;
    root["vm_uuid"] = bset.vm_uuid;
    root["type"] = bset.type;

    Json::Value vm;
    vm["uuid"] = bset.vm.uuid;

    for (const auto& m : bset.vm.allowed_operations) {
        vm["allowed_operations"].append(m);
    }

    vm["power_state"] = bset.vm.power_state;
    vm["name_label"] = bset.vm.name_label;
    vm["name_description"] = bset.vm.name_description;
    vm["user_version"] = bset.vm.user_version;
    vm["is_a_template"] = bset.vm.is_a_template;
    vm["memory_overhead"] = bset.vm.memory_overhead;
    vm["memory_target"] = bset.vm.memory_target;
    vm["memory_static_max"] = bset.vm.memory_static_max;
    vm["memory_dynamic_max"] = bset.vm.memory_dynamic_max;
    vm["memory_dynamic_min"] = bset.vm.memory_dynamic_min;
    vm["memory_static_min"] = bset.vm.memory_static_min;

    Json::Value vcpus_params(Json::arrayValue);
    for (const auto& vc : bset.vm.vcpus_params) {
        Json::Value ob;
        ob["key"] = vc.first;
        ob["value"] = vc.second;
        vcpus_params.append(ob);
    }
    vm["vcpus_params"] = vcpus_params;

    vm["vcpus_max"] = bset.vm.vcpus_max;
    vm["vcpus_at_startup"] = bset.vm.vcpus_at_startup;
    vm["actions_after_shutdown"] = bset.vm.actions_after_shutdown;
    vm["actions_after_reboot"] = bset.vm.actions_after_reboot;
    vm["actions_after_crash"] = bset.vm.actions_after_crash;

    vm["pv_bootloader"] = bset.vm.pv_bootloader;
    vm["pv_kernel"] = bset.vm.pv_kernel;
    vm["pv_ramdisk"] = bset.vm.pv_ramdisk;
    vm["pv_args"] = bset.vm.pv_args;
    vm["pv_bootloader_args"] = bset.vm.pv_bootloader_args;
    vm["pv_legacy_args"] = bset.vm.pv_legacy_args;
    vm["hvm_boot_policy"] = bset.vm.hvm_boot_policy;

    Json::Value hvm_boot_params(Json::arrayValue);
    for (const auto& h : bset.vm.hvm_boot_params) {
        Json::Value ob;
        ob["key"] = h.first;
        ob["value"] = h.second;
        hvm_boot_params.append(ob);
    }
    vm["hvm_boot_params"] = hvm_boot_params;

    vm["hvm_shadow_multiplier"] = bset.vm.hvm_shadow_multiplier;

    Json::Value platforms(Json::arrayValue);
    for (const auto& ps : bset.vm.platform) {
        Json::Value ob;
        ob["key"] = ps.first;
        ob["value"] = ps.second;
        platforms.append(ob);
    }
    vm["platform"] = platforms;

    Json::Value other_config(Json::arrayValue);
    for (const auto& h : bset.vm.other_config) {
        Json::Value ob;
        ob["key"] = h.first;
        ob["value"] = h.second;
        other_config.append(ob);
    }
    vm["other_config"] = other_config;

    Json::Value vbds(Json::arrayValue);
    for (const auto& b : bset.vm.vbds) {
        Json::Value vbd;
        vbd["uuid"] = b.uuid;
        vbd["bootable"] = b.bootable;
        vbd["device"] = b.device;
        vbd["userdevice"] = b.userdevice;

        Json::Value vdi;
        vdi["vdi"] = b.vdi.vdi;
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

    Json::Value vifs(Json::arrayValue);
    for (const auto& v : bset.vm.vifs) {
        Json::Value vif;
        vif["uuid"] = v.uuid;
        vif["device"] = v.device;
        vif["mac"] = v.mac;
        vif["mtu"] = v.mtu;

        Json::Value n;
        n["uuid"] = v.network.uuid;
        n["name_label"] = v.network.name_label;
        n["name_description"] = v.network.name_description;
        n["mtu"] = v.network.mtu;
        n["bridge"] = v.network.bridge;
        vif["network"] = n;
        vifs.append(vif);
    }
    vm["vifs"] = vifs;

    root["vm"] = vm;

    std::filesystem::path m(dir);
    m /= (bset.vm_name + "/" + VM_META_CONF);
    // std::string file = bset.vm_name + "/" + VM_META_CONF;
    std::ofstream output_file(m.string());
    output_file << root;
    output_file.close();

    return true;
}

bool Xe_Client::backup_vm_diff(const std::string &backup_dir, const std::string &vm_uuid)
{
    std::vector<struct backup_set> sets;
    if (!load_backup_sets(sets)) {
        std::cout << "Failed to get backup sets" << std::endl;
        return false;
    }

    // find the latest full backup set by vm_uuid
    auto it = std::find_if(sets.rbegin(), sets.rend(), [&vm_uuid](const struct backup_set& bset) {
        return bset.vm_uuid == vm_uuid && bset.type == BACKUP_TYPE_FULL;
    });

    if (it == sets.rend()) {
        std::cout << "Failed to find full backup set for vm: " << vm_uuid << std::endl;
        return false;
    }

    const auto& set_id = it->vm_name;
    std::cout << "Found full backup set: " << set_id << std::endl;
    std::filesystem::path m = std::filesystem::path(backup_dir) / set_id / VM_META_CONF;
    std::cout << "=== " << m.string() << std::endl;
    struct vm v;
    if (!load_vm_meta(m.string(), v)) {
        std::cout << "Failed to load vm meta: " << m.string() << std::endl;
        return false;
    }

    struct backup_set bt;
    if (!backup_vm_i(vm_uuid, backup_dir, bt, BACKUP_TYPE_DIFF, v)) {
        std::cout << "Failed to backup diff vm: " << vm_uuid << std::endl;
        return false;
    }

    bt.type = BACKUP_TYPE_DIFF;
    if (!add_backup_set(bt)) {
        std::cout << "Failed to add backup set: " << vm_uuid << std::endl;
        return false;
    }

    if (!add_vm_meta(backup_dir, bt)) {
        std::cout << "Failed to add vm meta: " << vm_uuid << std::endl;
        return false;
    }

    return true;
}

bool Xe_Client::backup_vm(const std::string &vm_uuid, const std::string &backup_dir)
{
    struct backup_set bt;
    struct vm v;
    if (!backup_vm_i(vm_uuid, backup_dir, bt, BACKUP_TYPE_FULL, v)) {
        std::cout << "Failed to backup vm: " << vm_uuid << std::endl;
        return false;
    }

    if (!add_backup_set(bt)) {
        std::cout << "Failed to add backup set: " << vm_uuid << std::endl;
        return false;
    }

    if (!add_vm_meta(backup_dir, bt)) {
        std::cout << "Failed to add vm meta: " << vm_uuid << std::endl;
        return false;
    }

    return true;
}

bool Xe_Client::pifs(std::vector<std::string>& ips, xen_host host)
{
    xen_pif_set *pif_set;
    if (!xen_host_get_pifs(session_, &pif_set, host) || pif_set->size == 0) {
        std::cout << "Failed to get pifs" << std::endl;
        return false;
    }

    auto s = make_deleter(pif_set, [](xen_pif_set* s) {
        xen_pif_set_free(s);
    });

    for (int i = 0; i < pif_set->size; i++) {
        xen_pif_record *pif_record = nullptr;
        if (!xen_pif_get_record(session_, &pif_record, pif_set->contents[i])) {
            std::cout << "Failed to get pif record" << std::endl;
            return false;
        }

        if (pif_record->currently_attached) {
            std::cout << "ip: " << pif_record->ip << std::endl;
            ips.emplace_back(pif_record->ip);
        }

        xen_pif_record_free(pif_record);
    }

    return true;
}

bool Xe_Client::backup_vm_i(const std::string &vm_uuid,
                            const std::string &backup_dir,
                            struct backup_set &bt,
                            const std::string& backup_type,
                            const struct vm& full_v)
{
    xen_vm backup_vm = nullptr;
    if (!xen_vm_get_by_uuid(session_, &backup_vm, (char *)vm_uuid.c_str())) {
        std::cout << "Failed to get vm by uuid: " << vm_uuid << std::endl;
        return false;
    }

    xen_vm_record *vm_record = nullptr;
    if (!xen_vm_get_record(session_, &vm_record, backup_vm)) {
        std::cout << "Failed to get vm record" << std::endl;
        return false;
    }

    std::string name = vm_record->name_label;
    std::string desc = vm_record->name_description;

    // choose pif to backup
    std::vector<std::string> ips;
    pifs(ips, vm_record->affinity->u.handle);

    std::cout << "choose ip to backup: " << std::endl;
    int index = 0;
    for (const auto& ip : ips) {
        std::cout << index++ << ": " << ip << std::endl;
    }

    char buf[10];
    std::cin.getline(buf, 10);
    int n = atoi(buf);
    if (n < 0 || n >= ips.size()) {
        std::cout << "Invalid input" << std::endl;
        return false;
    }
    const std::string& host_ip = ips[n];
    std::cout << "== host ip: " << host_ip << std::endl;

    xen_vm_record_free(vm_record);

    const auto& cur_date = current_time_str();
    bt.date = cur_date;
    bt.type = BACKUP_TYPE_FULL;
    const auto& snap_name = vm_uuid + "_" + cur_date;
    std::cout << "snap_name: " << snap_name << std::endl;
    bt.vm_name = snap_name;
    bt.vm_uuid = vm_uuid;

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
        delete_snapshot(snap_handle);
        return false;
    }
    v.name_label = name;
    v.name_description = desc;

    // mkdir(snap_name.c_str(), 0777);
    bool ret = true;
    for (const auto &vb : v.vbds) {
        std::string basevdi;
        if (backup_type == BACKUP_TYPE_DIFF) {
            basevdi = find_basevdi_by_userdevice(full_v, vb.userdevice);
            if (basevdi.empty()) {
                std::cout << "Failed to find basevdi by userdevice: " << vb.userdevice << std::endl;
                ret = false;
                break;
            }
        }

        xen_task task = nullptr;
        std::string task_name("export_raw_vdi");
        if (!xen_task_create(session_, &task, (char*)task_name.c_str(),
                             const_cast<char *>("task"))) {
            std::cout << "Failed to create task" << std::endl;
            ret = false;
            break;
        }

        std::filesystem::path file(backup_dir);
        file /= snap_name;
        if (!std::filesystem::exists(file)) {
            std::filesystem::create_directory(file);
        }
        file /= vb.vdi.uuid + ".vhd";

        const auto& url = export_url(host_ip, task, vb.vdi.vdi, basevdi);
        std::thread t(&Xe_Client::http_download, this, url, file.string());
        progress(task);
        t.join();
        xen_task_free(task);
    }

    if (!ret) {
        delete_snapshot(snap_handle);
        xen_vm_free(snap_handle);
        return false;
    }

    if (backup_type == BACKUP_TYPE_DIFF)
        delete_snapshot(snap_handle);

    bt.vm = std::move(v);
    xen_vm_free(snap_handle);

    return true;
}

void Xe_Client::http_download(const std::string &url, const std::string &file)
{
    std::cout << "start to http download" << std::endl;
    CURL *curl = nullptr;
    CURLcode res;
    long http_code;
    std::ofstream output_file(file, std::ios::binary);

    curl = curl_easy_init();

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefile);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &output_file);
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
        //curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
        res = curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        curl_easy_cleanup(curl);
    }

    output_file.close();
    std::cout << "curl rc :" << res << std::endl;
    std::cout << "http code: " << http_code << std::endl;
}

void Xe_Client::http_upload(const std::string &url, const std::string &file)
{
    std::cout << "start to http upload" << std::endl;
    CURL *curl = nullptr;
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

std::string Xe_Client::export_url(const std::string& host,
                                  xen_task task,
                                  const std::string& vdi,
                                  const std::string& base)
{
    // std::string url = "http://172.16.2.163";
    std::string url = host;
    url.append("/export_raw_vdi?session_id=");
    url.append(session_->session_id);
    url.append("&task_id=");
    url.append((char *)task);
    url.append("&vdi=");
    url.append(vdi);
    url.append("&format=vhd");

    if (!base.empty()) {
        url.append("&base=");
        url.append(base);
    }

    std::cout << "export_url: " << url << std::endl;
    return url;
}

std::string Xe_Client::import_url(xen_task task, const std::string& vdi)
{
    std::string url = host_;
    url.append("/import_raw_vdi?session_id=");
    url.append(session_->session_id);
    url.append("&task_id=");
    url.append((char *)task);
    url.append("&vdi=");
    url.append(vdi);
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

bool Xe_Client::scan_networks()
{
    xen_network_set* network_set = nullptr;
    if (!xen_network_get_all(session_, &network_set)) {
        std::cout << "Failed to get network set" << std::endl;
        return false;
    }

    std::cout << "================ network ================" << std::endl;
    for (int i = 0; i < network_set->size; i++) {
        xen_network_record *network_record = nullptr;
        if (!xen_network_get_record(session_, &network_record, network_set->contents[i])) {
            std::cout << "Failed to get network record" << std::endl;
            return false;
        }

        std::cout << "uuid: " << network_record->uuid << std::endl;
        std::cout << "  name_label: " << network_record->name_label << std::endl;
        std::cout << "  name_description: " << network_record->name_description << std::endl;
        std::cout << "  bridge: " << network_record->bridge << std::endl;
        std::cout << "  MTU: " << network_record->mtu << std::endl;
        std::cout << "  managed " << network_record->managed << std::endl;
    }
    std::cout << "======================================" << std::endl;

    return true;
}

bool Xe_Client::restore_vm(const std::string& storage_dir,
                           const std::string& set_id,
                           const std::string& sr_uuid)
{
    std::vector<struct backup_set> sets;
    if (!load_backup_sets(sets)) {
        std::cout << "Failed to get backup sets" << std::endl;
        return false;
    }

    auto it = std::find_if(sets.begin(), sets.end(), [&set_id](const struct backup_set& bset) {
        return bset.vm_name == set_id;
    });

    if (it == sets.end()) {
        std::cout << "Failed to find backup set: " << set_id << std::endl;
        return false;
    }

    std::string type = it->type;
    std::string new_uuid;
    if (type == BACKUP_TYPE_FULL) {
        std::cout << "full_set_id: " << set_id << std::endl;
        if (!restore_vm_full(storage_dir, set_id, sr_uuid, new_uuid)) {
            std::cout << "Failed to restore vm " << set_id << std::endl;
            return false;
        }
    } else {
        std::string vm_uuid = it->vm_uuid;

        // diff restore, find the latest full backup set
        auto it2 = std::find_if(sets.rbegin(), sets.rend(), [&vm_uuid](const struct backup_set& bset) {
            return bset.vm_uuid == vm_uuid && bset.type == BACKUP_TYPE_FULL;
        });

        if (it2 == sets.rend()) {
            std::cout << "Failed to find full backup set for vm: " << vm_uuid << std::endl;
            return false;
        }

        std::string full_set_id = it2->vm_name;
        std::cout << "full_set_id: " << full_set_id << std::endl;
        if (!restore_vm_full(storage_dir, full_set_id, sr_uuid, new_uuid)) {
            std::cout << "Failed to restore vm " << set_id << std::endl;
            return false;
        }

        std::cout << "==== start to restore diff set: " << set_id << std::endl;
        if (!restore_vm_diff(storage_dir, set_id, sr_uuid, new_uuid)) {
            std::cout << "Failed to restore vm " << set_id << std::endl;
            return false;
        }
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
        std::cout << "  set_id: " << b["set_id"].asString() << ", type: " << b["type"].asString() << std::endl;
    }
    std::cout << "=====================================" << std::endl;
    return true;
}

void Xe_Client::update_backup_set(const std::vector<struct backup_set>& bsets)
{
    Json::Value root;
    Json::Value sets(Json::arrayValue);
    for (const auto& b : bsets) {
        Json::Value s;
        s["set_id"] = b.vm_name;
        s["type"] = b.type;
        s["vm_uuid"] = b.vm_uuid;
        s["date"] = b.date;
        sets.append(s);
    }
    root["sets"] = sets;

    std::ofstream out(BACKUP_SET_CONF);
    out << root;
    out.close();
}

bool Xe_Client::rm_backupset(const std::string& backup_dir, const std::string& set_id)
{
    std::vector<struct backup_set> sets;
    if (!load_backup_sets(sets)) {
        std::cout << "Failed to get backup sets" << std::endl;
        return false;
    }

    std::filesystem::path m;
    if (set_id == "all") {
        for (const auto& s : sets) {
            try {
                m.clear();
                m /= (backup_dir + "/" + s.vm_name);
                if (std::filesystem::is_directory(m)) {
                    std::filesystem::remove_all(m);
                }
            } catch (const std::exception& ex) {
                std::cerr << "err: " << ex.what() << std::endl;
            }
        }

        sets.clear();
        update_backup_set(sets);
    }

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

    for (const auto& op : root["vm"]["allowed_operations"]) {
        vm.allowed_operations.emplace_back(op.asInt());
    }

    vm.name_label = root["vm"]["name_label"].asString();
    vm.name_description = root["vm"]["name_description"].asString();
    vm.power_state = root["vm"]["power_state"].asInt();
    vm.memory_static_max = root["vm"]["memory_static_max"].asInt64();
    vm.memory_dynamic_max = root["vm"]["memory_dynamic_max"].asInt64();
    vm.memory_dynamic_min = root["vm"]["memory_dynamic_min"].asInt64();
    vm.memory_static_min = root["vm"]["memory_static_min"].asInt64();

    for (const auto& h : root["vm"]["vcpus_params"]) {
        vm.vcpus_params.emplace(h["key"].asString(), h["value"].asString());
    }

    vm.vcpus_max = root["vm"]["vcpus_max"].asInt64();
    vm.vcpus_at_startup = root["vm"]["vcpus_at_startup"].asInt64();
    vm.actions_after_shutdown = root["vm"]["actions_after_shutdown"].asInt64();
    vm.actions_after_reboot = root["vm"]["actions_after_reboot"].asInt64();
    vm.actions_after_crash = root["vm"]["actions_after_crash"].asInt64();

    vm.pv_bootloader = root["vm"]["pv_bootloader"].asString();
    vm.pv_kernel = root["vm"]["pv_kernel"].asString();
    vm.pv_ramdisk = root["vm"]["pv_ramdisk"].asString();
    vm.pv_args = root["vm"]["pv_args"].asString();
    vm.pv_bootloader_args = root["vm"]["pv_bootloader_args"].asString();
    vm.pv_legacy_args = root["vm"]["pv_legacy_args"].asString();
    vm.hvm_boot_policy = root["vm"]["hvm_boot_policy"].asString();

    for (const auto& h : root["vm"]["hvm_boot_params"]) {
        vm.hvm_boot_params.emplace(h["key"].asString(), h["value"].asString());
    }

    vm.hvm_shadow_multiplier = root["vm"]["hvm_shadow_multiplier"].asDouble();

    for (const auto& p : root["vm"]["platform"]) {
        vm.platform.emplace(p["key"].asString(), p["value"].asString());
    }

    for (const auto& h : root["vm"]["other_config"]) {
        vm.other_config.emplace(h["key"].asString(), h["value"].asString());
    }

    for (const auto& vbd : root["vm"]["vbds"]) {
        struct vbd vb;
        vb.uuid = vbd["uuid"].asString();
        vb.bootable = vbd["bootable"].asBool();
        vb.device = vbd["device"].asString();
        vb.userdevice = vbd["userdevice"].asString();
        vb.vdi.uuid = vbd["vdi"]["uuid"].asString();
        vb.vdi.vdi = vbd["vdi"]["vdi"].asString();
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

bool Xe_Client::create_new_vm_by_meta(std::string& vm_uuid, const struct vm& v)
{
    xen_vm_record *record = xen_vm_record_alloc();

    record->allowed_operations = xen_vm_operations_set_alloc(v.allowed_operations.size());
    record->allowed_operations->size = 0;
    for (const auto& op : v.allowed_operations) {
        record->allowed_operations->contents[record->allowed_operations->size++] = (xen_vm_operations)op;
    }

    //record->name_label = strdup(v.name_label.c_str());
    std::string name = "testvm2";
    record->name_label = strdup(name.c_str());
    record->name_description = strdup(v.name_description.c_str());
    record->user_version = v.user_version;
    record->is_a_template = false;
    record->memory_overhead = v.memory_overhead;
    record->memory_target = v.memory_target;
    record->memory_static_max = v.memory_static_max;
    record->memory_static_min = v.memory_static_min;
    record->memory_dynamic_max = v.memory_dynamic_max;
    record->memory_dynamic_min = v.memory_dynamic_min;

    record->vcpus_params = xen_string_string_map_alloc(v.vcpus_params.size());
    record->vcpus_params->size = 0;
    for (const auto& vc : v.vcpus_params) {
        record->vcpus_params->contents[record->vcpus_params->size].key = strdup(vc.first.c_str());
        record->vcpus_params->contents[record->vcpus_params->size++].val = strdup(vc.second.c_str());
    }

    record->vcpus_max = v.vcpus_max;
    record->vcpus_at_startup = v.vcpus_at_startup;
    record->actions_after_shutdown = (xen_on_normal_exit)v.actions_after_shutdown;
    record->actions_after_reboot = (xen_on_normal_exit)v.actions_after_reboot;
    record->actions_after_crash = (xen_on_crash_behaviour)v.actions_after_crash;

    record->pv_bootloader = strdup(v.pv_bootloader.c_str());
    record->pv_kernel = strdup(v.pv_kernel.c_str());
    record->pv_ramdisk = strdup(v.pv_ramdisk.c_str());
    record->pv_args = strdup(v.pv_args.c_str());
    record->pv_bootloader_args = strdup(v.pv_bootloader_args.c_str());
    record->pv_legacy_args = strdup(v.pv_legacy_args.c_str());
    record->hvm_boot_policy = strdup(v.hvm_boot_policy.c_str());

    record->hvm_boot_params = xen_string_string_map_alloc(v.hvm_boot_params.size());
    record->hvm_boot_params->size = 0;
    for (const auto& op : v.hvm_boot_params) {
        record->hvm_boot_params->contents[record->hvm_boot_params->size].key = strdup(op.first.c_str());
        record->hvm_boot_params->contents[record->hvm_boot_params->size++].val = strdup(op.second.c_str());
    }

    record->hvm_shadow_multiplier = v.hvm_shadow_multiplier;

    record->platform = xen_string_string_map_alloc(v.platform.size());
    record->platform->size = 0;
    for (const auto& op : v.platform) {
        record->platform->contents[record->platform->size].key = strdup(op.first.c_str());
        record->platform->contents[record->platform->size++].val = strdup(op.second.c_str());
        std::cout << "platform key: " << op.first << " val: " << op.second << std::endl;
    }

    record->other_config = xen_string_string_map_alloc(v.other_config.size());
    record->other_config->size = 0;
    for (const auto& op : v.other_config) {
        record->other_config->contents[record->other_config->size].key = strdup(op.first.c_str());
        record->other_config->contents[record->other_config->size++].val = strdup(op.second.c_str());
    }

    record->is_a_snapshot = false;

    xen_vm vm = NULL;
    xen_vm_create(session_, &vm, record);
    if ((!session_->ok) || (vm == nullptr)) {
        std::cout << "Failed to create vm" << std::endl;
        print_error(session_);
        xen_vm_record_free(record);
        return false;
    }

    char *vm_id;

    if (!xen_vm_get_uuid(session_, &vm_id, vm)) {
        std::cout << "Failed to get vm uuid" << std::endl;
        xen_vm_record_free(record);
        return false;
    }

    vm_uuid = vm_id;
    xen_uuid_free(vm_id);

    struct vm v2;
    if (!get_vm(vm, v2)) {
        std::cout << "Failed to get vm" << std::endl;
        xen_vm_record_free(record);
        return false;
    }

    dump_vm(v2);

    xen_vm_record_free(record);
    return true;
}

bool Xe_Client::create_new_vm(const std::string& storage_dir,
                              const std::string& set_id,
                              std::string& vm_uuid,
                              struct vm& v,
                              bool template_flag)
{
    if (template_flag) {
        return create_new_vm_by_template(vm_uuid);
    }

    std::filesystem::path meta_file(storage_dir);
    meta_file /= (set_id + "/" + VM_META_CONF);
    // std::string meta_file = set_id + "/" + VM_META_CONF;
    if (!load_vm_meta(meta_file.string(), v)) {
        std::cout << "Failed to load vm meta from " << meta_file << std::endl;
        return false;
    }

    if (!create_new_vm_by_meta(vm_uuid, v)) {
        std::cout << "Failed to create vm by meta" << std::endl;
        return false;
    }

    return true;
}

bool Xe_Client::create_new_vm_by_template(std::string& vm_uuid)
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

bool Xe_Client::restore_vm_diff(const std::string& storage_dir,
                                const std::string& set_id,
                                const std::string& sr_uuid,
                                const std::string& vm_uuid)
{
    // load diff vm info
    std::filesystem::path meta_file(storage_dir);
    meta_file /= (set_id + "/" + VM_META_CONF);
    struct vm diff_v;
    if (!load_vm_meta(meta_file.string(), diff_v)) {
        std::cout << "Failed to load vm meta from " << meta_file << std::endl;
        return false;
    }

    xen_vm vm;
    if (!xen_vm_get_by_uuid(session_, &vm, (char*)vm_uuid.c_str())) {
        std::cout << "Failed to get vm by " << vm_uuid << std::endl;
        return false;
    }

    struct vm full_v;
    if (!get_vm(vm, full_v)) {
        std::cout << "Failed to get vm" << std::endl;
    }
    xen_vm_free(vm);

    for (const auto& vb : diff_v.vbds) {
        std::string vdi = find_basevdi_by_userdevice(full_v, vb.userdevice);
        if (vdi.empty()) {
            std::cout << "Failed to find base vdi by userdevice " << vb.userdevice << std::endl;
            return false;
        }

        xen_task task = nullptr;
        std::string task_name("import_raw_vdi");
        if (!xen_task_create(session_, &task, (char*)task_name.c_str(),
                             const_cast<char *>("task"))) {
            std::cout << "Failed to create task" << std::endl;
            return false;
        }

        std::string url = import_url(task, vdi);

        std::filesystem::path file(storage_dir);
        file /= (set_id + "/" + vb.vdi.uuid + ".vhd");
        std::thread t(&Xe_Client::http_upload, this, url, file.string());
        progress(task);
        t.join();
    }

    return true;
}

bool Xe_Client::restore_vm_full(const std::string& storage_dir,
                                const std::string& set_id,
                                const std::string& sr_uuid,
                                std::string& vm_uuid)
{
    bool template_flag = false;
    std::string new_vm_uuid;
    struct vm v;
    if (!create_new_vm(storage_dir, set_id, new_vm_uuid, v, template_flag)) {
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

        xen_vdi vdi0 = nullptr;
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

        xen_vm_record_opt* vm_record_opt = xen_vm_record_opt_alloc();
        vm_record_opt->is_record = false;
        vm_record_opt->u.handle = new_vm2;

        xen_vdi_record_opt* vdi0_record_opt = xen_vdi_record_opt_alloc();
        vdi0_record_opt->is_record = false;
        vdi0_record_opt->u.handle = vdi0;

        xen_string_string_map* qos_algorithm_params = xen_string_string_map_alloc(0);
        xen_string_string_map* vbd_other_config = xen_string_string_map_alloc(0);
        xen_vbd_record *vbd0_record = xen_vbd_record_alloc();
        vbd0_record->vm = vm_record_opt;
        vbd0_record->vdi = vdi0_record_opt;
        vbd0_record->userdevice = strdup(vb.userdevice.c_str());
        vbd0_record->device = strdup(vb.device.c_str());
        vbd0_record->type = vbd_type_disk;
        vbd0_record->mode = XEN_VBD_MODE_RW;
        vbd0_record->qos_algorithm_params = qos_algorithm_params;
        vbd0_record->other_config = vbd_other_config;
        vbd0_record->bootable = true;

        xen_vbd vbd0 = nullptr;
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

        std::string url = import_url(task, (char*)vdi0);

        std::filesystem::path file(storage_dir);
        file /= (set_id + "/" + vb.vdi.uuid + ".vhd");
        //std::string file = set_id + "/" + vb.vdi.uuid + ".vhd";
        std::thread t(&Xe_Client::http_upload, this, url, file.string());
        progress(task);
        t.join();

        xen_vbd_record_free(vbd0_record);
    }

    if (template_flag) {
        xen_vm new_vm;
        if (!xen_vm_get_by_uuid(session_, &new_vm, (char*)new_vm_uuid.c_str())) {
            std::cout << "Failed to get vm by " << new_vm_uuid << std::endl;
            return false;
        }

        if (!xen_vm_provision(session_, new_vm)) {
            std::cout << "Failed to provision vm " << new_vm_uuid << std::endl;
            xen_session_clear_error(session_);
        }
    }
    vm_uuid = std::move(new_vm_uuid);

    return true;
}

std::string Xe_Client::find_basevdi_by_userdevice(const struct vm& v, const std::string& userdevice)
{
    dump_vm(v);
    std::string vdi;
    auto it = std::find_if(v.vbds.begin(), v.vbds.end(), [&userdevice](const struct vbd& vb) {
        return vb.userdevice == userdevice;
    });

    if (it != v.vbds.end()) {
        vdi = it->vdi.vdi;
    }

    return vdi;
}

bool Xe_Client::delete_snapshot(xen_vm vm)
{
    xen_vbd_set *vbd_set = nullptr;
    if (!xen_vm_get_vbds(session_, &vbd_set, vm)) {
        std::cout << "Failed to get vbds of snapshot" << std::endl;
    }

    if (!vbd_set) {
        std::cout << "vbd_set is null" << std::endl;
        return false;
    }

    for (int i = 0; i < vbd_set->size; ++i) {
        xen_vbd vbd = vbd_set->contents[i];
        xen_vbd_record *vbd_record = nullptr;
        if (!xen_vbd_get_record(session_, &vbd_record, vbd)) {
            print_error(session_);
            std::cout << "Failed to get vbd record" << std::endl;
            xen_vbd_set_free(vbd_set);
            return false;
        }

        if (vbd_record->type != XEN_VBD_TYPE_DISK) {
            xen_vbd_record_free(vbd_record);
            continue;
        }
        xen_vbd_record_free(vbd_record);

        xen_vdi vdi = nullptr;
        if (!xen_vbd_get_vdi(session_, &vdi, vbd)) {
            std::cout << "Failed to get vdi by vbd" << std::endl;
            xen_vbd_set_free(vbd_set);
            return false;
        }

        if (!vdi) {
            std::cout << "vdi is null" << std::endl;
            xen_vbd_set_free(vbd_set);
            return false;
        }

        if (!xen_vbd_destroy(session_, vbd)) {
            std::cout << "Failed to destroy vbd" << std::endl;
            xen_vdi_free(vdi);
            xen_vbd_set_free(vbd_set);
            return false;
        }

        if (!xen_vdi_destroy(session_, vdi)) {
            std::cout << "Failed to destroy vdi" << std::endl;
            xen_vdi_free(vdi);
            xen_vbd_set_free(vbd_set);
            return false;
        }

        xen_vdi_free(vdi);
    }

    if (!xen_vm_destroy(session_, vm)) {
        std::cout << "Failed to destroy snapshot" << std::endl;
        return false;
    }

    xen_vbd_set_free(vbd_set);
    return true;
}
