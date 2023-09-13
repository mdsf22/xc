#ifndef XE_CLIENT_
#define XE_CLIENT_

extern "C"
{
#include <xen/api/xen_all.h>
}
#include <string>
#include <vector>
#include <map>

struct network {
    std::string uuid;
    std::string name_label;
    std::string name_description;
    int64_t mtu;
    std::string bridge;
    bool managed;
};

struct vif {
    std::string uuid;
    std::string device;
    std::string mac;
    int64_t mtu;
    struct network network;
};

struct vdi {
    std::string uuid;
    std::string vdi;
    std::string name_label;
    std::string name_description;
    int64_t virtual_size;
    int64_t physical_utilisation;
    int type;
    bool sharable;
    bool read_only;
};

struct vbd {
    std::string uuid;
    std::string device;
    std::string userdevice;
    bool bootable;
    struct vdi vdi;
};

struct vm {
    std::string uuid;
    std::vector<int> allowed_operations;
    int power_state;

    std::string name_label;
    std::string name_description;
    int64_t user_version;
    bool is_a_template;
    //suspend_vdi
    //resident_on
    //affinity
    int64_t memory_overhead;
    int64_t memory_target;
    int64_t memory_static_max;
    int64_t memory_dynamic_max;
    int64_t memory_dynamic_min;
    int64_t memory_static_min;
    std::map<std::string, std::string> vcpus_params;
    int64_t vcpus_max;
    int64_t vcpus_at_startup;
    int actions_after_shutdown;
    int actions_after_reboot;
    int actions_after_crash;

    std::string pv_bootloader;
    std::string pv_kernel;
    std::string pv_ramdisk;
    std::string pv_args;
    std::string pv_bootloader_args;
    std::string pv_legacy_args;
    std::string hvm_boot_policy;

    std::map<std::string, std::string> hvm_boot_params;
    double hvm_shadow_multiplier;
    std::map<std::string, std::string> platform;

    std::map<std::string, std::string> other_config;

    std::vector<struct vbd> vbds;
    std::vector<struct vif> vifs;
    std::string host_uuid;
};

struct backup_set {
    std::string vm_name;
    std::string vm_uuid;
    std::string date;
    std::string type;     // full or diff
    struct vm vm;
};

struct host {
    std::string uuid;
    std::string host;
    std::string address;
    std::vector<struct vm> vms;
};

struct sr {
    std::string uuid;
    std::string name_label;
    std::string name_description;
    std::string type;
    int64_t physical_utilisation;
    int64_t physical_size;
};

class Xe_Client
{
public:
    Xe_Client(std::string host, std::string user, std::string pass);
    ~Xe_Client();

    bool connect();
    bool scan_vms();
    bool scan_srs();
    bool scan_networks();
    bool scan_backsets();
    bool scan_all();

    bool backup_vm(const std::string &vm_uuid, const std::string &backup_dir);
    bool backup_vm_diff(const std::string &backup_dir, const std::string &vm_uuid);

    bool restore_vm(const std::string& storage_dir,
                    const std::string& set_id);

    bool rm_backupset(const std::string& backup_dir, const std::string& set_id);
private:
    xen_session* get_session() const { return session_; }

    bool dump(const std::map<std::string, struct host>& hosts);

    bool vms(std::vector<struct vm>& vms);
    bool srs(std::vector<struct sr>& srs);
    bool networks(std::vector<struct network>& networks);
    bool hosts(std::map<std::string, struct host> &host);
    bool pifs(std::vector<std::string>& pifs, xen_host host);

    bool write_to_json();
    bool backupset_list(std::vector<struct backup_set>& bsets);

    bool restore_vdi(const std::string& storage_dir,
                     const std::string& set_id,
                     const std::string& sr_uuid,
                     const std::string& vm_uuid,
                     std::vector<struct vbd>& vbds);

    bool restore_vif(const std::string& vm_uuid,
                     const std::string& network_uuid,
                     const struct vif& vif);

    bool get_vm(xen_vm x_vm, struct vm& vm, bool snapshot = false);
    std::string export_url(const std::string& host,
                           xen_task task,
                           const std::string& vdi,
                           const std::string& base);
    bool get_vifs(xen_vm x_vm, std::vector<struct vif>& vifs);
    std::string import_url(xen_task task, const std::string& vdi);
    void progress(xen_task task);
    bool load_vm_meta(const std::string& file, struct vm &vm);

    bool backup_vm_i(const std::string &vm_uuid,
                     const std::string &backup_dir,
                     struct backup_set &bt,
                     const std::string& backup_type,
                     const struct vm& full_v);

    void http_download(const std::string &url, const std::string &file);
    void http_upload(const std::string &url, const std::string &file);

    bool restore_vm_full(const std::string& storage_dir,
                         const std::string& set_id,
                         std::string& vm_uuid);
    bool restore_vm_diff(const std::string& storage_dir,
                         const std::string& set_id,
                         const std::string& vm_uuid);

    bool add_backup_set(const struct backup_set &bset);
    bool load_backup_sets(std::vector<struct backup_set>& bsets);
    bool add_vm_meta(const std::string& dir, const struct backup_set &bset);

    bool get_vbds(struct vm &v, xen_vm_record *vm_record);
    bool create_new_vm(const std::string& storage_dir,
                       const std::string& set_id,
                       std::string& vm_uuid,
                       struct vm& v,
                       bool template_flag = true);
    bool create_new_vm_by_meta(std::string& vm_uuid, const struct vm& v);
    bool create_new_vm_by_template(std::string& vm_uuid);

    void dump_vm(const struct vm& v);
    void dump_vbd(const struct vbd& vb);
    void dump_vif(const struct vif& vf);
    void dump_sr(const struct sr& sr);
    void dump_backupset(const struct backup_set& bset);

    std::string find_basevdi_by_userdevice(const struct vm& v, const std::string& userdevice);
    void update_backup_set(const std::vector<struct backup_set>& bsets);
    bool delete_snapshot(xen_vm vm);

    bool scan_pif(struct xen_pif_record_opt_set *pifs);
private:
    xen_session* session_;
    std::string host_;
    std::string user_;
    std::string pass_;

    std::map<std::string, struct host> hosts_;
    std::vector<struct sr> srs_;
    std::vector<struct backup_set> backup_sets_;
};

#endif // XE_CLIENT_
