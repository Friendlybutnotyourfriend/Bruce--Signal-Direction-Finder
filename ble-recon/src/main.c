/* BLE Recon Interactive - passive/active BLE observation and diagnostics */
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/util.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/addr.h>
#include <zephyr/bluetooth/gap.h>
#include <zephyr/bluetooth/hci_types.h>
#include <zephyr/bluetooth/assigned_numbers.h>
#include <zephyr/shell/shell.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define MAX_DEVICES 96
#define MAX_NAME_LEN 32
#define MAX_UUID16 12
#define MAX_MFR_DATA 28
#define MAX_SVC_DATA 30
#define MAX_RAW_DATA 64

struct ad_parse_ctx {
    char name[MAX_NAME_LEN];
    bool has_name;
    uint8_t flags;
    bool has_flags;
    int8_t ad_tx_power;
    bool has_ad_tx_power;
    uint16_t appearance;
    bool has_appearance;
    uint16_t uuids16[MAX_UUID16];
    uint8_t uuid16_count;
    uint16_t mfr_id;
    bool has_mfr;
    uint8_t mfr_data[MAX_MFR_DATA];
    uint8_t mfr_len;
    uint16_t svc16_uuid;
    bool has_svc16;
    uint8_t svc16_data[MAX_SVC_DATA];
    uint8_t svc16_len;
    bool has_fe9f;
    bool has_fcf1;
};

struct observed_device {
    bool used;
    bt_addr_le_t addr;
    char addr_str[BT_ADDR_LE_STR_LEN];
    int8_t last_rssi;
    int8_t min_rssi;
    int8_t max_rssi;
    int64_t rssi_sum;
    uint32_t packet_count;
    uint32_t adv_count;
    uint32_t scan_rsp_count;
    int64_t first_seen_ms;
    int64_t last_seen_ms;
    int64_t last_adv_ms;
    uint64_t cadence_sum_ms;
    uint32_t cadence_samples;
    uint8_t last_adv_type;
    uint16_t last_adv_props;
    uint8_t last_primary_phy;
    uint8_t last_secondary_phy;
    int8_t controller_tx_power;
    bool has_controller_tx_power;
    char name[MAX_NAME_LEN];
    bool has_name;
    uint8_t flags;
    bool has_flags;
    int8_t ad_tx_power;
    bool has_ad_tx_power;
    uint16_t appearance;
    bool has_appearance;
    uint16_t uuids16[MAX_UUID16];
    uint8_t uuid16_count;
    uint16_t mfr_id;
    bool has_mfr;
    uint8_t mfr_data[MAX_MFR_DATA];
    uint8_t mfr_len;
    uint16_t svc16_uuid;
    bool has_svc16;
    uint8_t svc16_data[MAX_SVC_DATA];
    uint8_t svc16_len;
    bool has_fe9f;
    bool has_fcf1;
    uint8_t raw[MAX_RAW_DATA];
    uint8_t raw_len;
    bool raw_truncated;
};

static struct observed_device devices[MAX_DEVICES];
K_MUTEX_DEFINE(devices_lock);
static bool scanning;
static bool active_scan = true;
static bool live_enabled;
static bool live_raw;
static int selected_index = -1;
static int display_rssi_floor = -100;

static const char *addr_class(const bt_addr_le_t *addr)
{
    if (addr->type == BT_ADDR_LE_PUBLIC) return "PUBLIC";
    if (addr->type == BT_ADDR_LE_PUBLIC_ID) return "PUBLIC_ID";
    if (addr->type == BT_ADDR_LE_RANDOM || addr->type == BT_ADDR_LE_RANDOM_ID ||
        addr->type == BT_ADDR_LE_UNRESOLVED) {
        uint8_t top = (addr->a.val[5] >> 6) & 0x03;
        if (top == 0x03) return "STATIC";
        if (top == 0x01) return "RPA";
        if (top == 0x00) return "NRPA";
        return "RANDOM?";
    }
    return "OTHER";
}

static const char *adv_type_str(uint8_t type)
{
    switch (type) {
    case BT_GAP_ADV_TYPE_ADV_IND: return "ADV_IND";
    case BT_GAP_ADV_TYPE_ADV_DIRECT_IND: return "DIRECT";
    case BT_GAP_ADV_TYPE_ADV_SCAN_IND: return "SCAN_IND";
    case BT_GAP_ADV_TYPE_ADV_NONCONN_IND: return "NONCONN";
    case BT_GAP_ADV_TYPE_SCAN_RSP: return "SCAN_RSP";
    case BT_GAP_ADV_TYPE_EXT_ADV: return "EXT_ADV";
    default: return "UNKNOWN";
    }
}

static const char *company_name(uint16_t id)
{
    switch (id) {
    case 0x004C: return "Apple";
    case 0x0006: return "Microsoft";
    case 0x00E0: return "Google";
    case 0x0075: return "Samsung";
    case 0x0059: return "Nordic";
    default: return "Unknown";
    }
}

static const char *phy_str(uint8_t phy)
{
    switch (phy) {
    case BT_GAP_LE_PHY_1M: return "1M";
    case BT_GAP_LE_PHY_2M: return "2M";
    case BT_GAP_LE_PHY_CODED: return "CODED";
    case BT_GAP_LE_PHY_NONE: return "-";
    default: return "?";
    }
}

static bool has_uuid16(const uint16_t *list, uint8_t count, uint16_t uuid)
{
    for (uint8_t i = 0; i < count; i++) if (list[i] == uuid) return true;
    return false;
}

static void add_uuid16(struct ad_parse_ctx *ctx, uint16_t uuid)
{
    if (!has_uuid16(ctx->uuids16, ctx->uuid16_count, uuid) && ctx->uuid16_count < MAX_UUID16)
        ctx->uuids16[ctx->uuid16_count++] = uuid;
    if (uuid == 0xFE9F) ctx->has_fe9f = true;
    if (uuid == 0xFCF1) ctx->has_fcf1 = true;
}

static bool ad_parse_cb(struct bt_data *data, void *user_data)
{
    struct ad_parse_ctx *ctx = user_data;
    switch (data->type) {
    case BT_DATA_NAME_COMPLETE:
    case BT_DATA_NAME_SHORTENED: {
        size_t n = MIN((size_t)data->data_len, sizeof(ctx->name) - 1);
        memcpy(ctx->name, data->data, n);
        ctx->name[n] = '\0';
        ctx->has_name = true;
        break;
    }
    case BT_DATA_FLAGS:
        if (data->data_len >= 1) { ctx->flags = data->data[0]; ctx->has_flags = true; }
        break;
    case BT_DATA_TX_POWER:
        if (data->data_len >= 1) { ctx->ad_tx_power = (int8_t)data->data[0]; ctx->has_ad_tx_power = true; }
        break;
    case BT_DATA_GAP_APPEARANCE:
        if (data->data_len >= 2) { ctx->appearance = sys_get_le16(data->data); ctx->has_appearance = true; }
        break;
    case BT_DATA_UUID16_SOME:
    case BT_DATA_UUID16_ALL:
        for (uint8_t i = 0; i + 1 < data->data_len; i += 2) add_uuid16(ctx, sys_get_le16(&data->data[i]));
        break;
    case BT_DATA_SVC_DATA16:
        if (data->data_len >= 2) {
            uint16_t uuid = sys_get_le16(data->data);
            add_uuid16(ctx, uuid);
            ctx->svc16_uuid = uuid;
            ctx->has_svc16 = true;
            uint8_t payload_len = data->data_len - 2;
            ctx->svc16_len = MIN(payload_len, (uint8_t)sizeof(ctx->svc16_data));
            if (ctx->svc16_len) memcpy(ctx->svc16_data, &data->data[2], ctx->svc16_len);
        }
        break;
    case BT_DATA_MANUFACTURER_DATA:
        if (data->data_len >= 2) {
            ctx->mfr_id = sys_get_le16(data->data);
            ctx->has_mfr = true;
            uint8_t payload_len = data->data_len - 2;
            ctx->mfr_len = MIN(payload_len, (uint8_t)sizeof(ctx->mfr_data));
            if (ctx->mfr_len) memcpy(ctx->mfr_data, &data->data[2], ctx->mfr_len);
        }
        break;
    default: break;
    }
    return true;
}

static int find_device_locked(const bt_addr_le_t *addr)
{
    for (int i = 0; i < MAX_DEVICES; i++)
        if (devices[i].used && bt_addr_le_cmp(&devices[i].addr, addr) == 0) return i;
    return -1;
}

static int alloc_device_locked(const bt_addr_le_t *addr)
{
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (!devices[i].used) {
            memset(&devices[i], 0, sizeof(devices[i]));
            devices[i].used = true;
            bt_addr_le_copy(&devices[i].addr, addr);
            bt_addr_le_to_str(addr, devices[i].addr_str, sizeof(devices[i].addr_str));
            devices[i].min_rssi = 127;
            devices[i].max_rssi = -127;
            return i;
        }
    }
    int oldest = -1;
    int64_t oldest_seen = INT64_MAX;
    for (int i = 0; i < MAX_DEVICES; i++) {
        if (i == selected_index) continue;
        if (devices[i].last_seen_ms < oldest_seen) { oldest_seen = devices[i].last_seen_ms; oldest = i; }
    }
    if (oldest >= 0) {
        memset(&devices[oldest], 0, sizeof(devices[oldest]));
        devices[oldest].used = true;
        bt_addr_le_copy(&devices[oldest].addr, addr);
        bt_addr_le_to_str(addr, devices[oldest].addr_str, sizeof(devices[oldest].addr_str));
        devices[oldest].min_rssi = 127;
        devices[oldest].max_rssi = -127;
    }
    return oldest;
}

static void merge_parsed_ad(struct observed_device *d, const struct ad_parse_ctx *ctx)
{
    if (ctx->has_name) { strncpy(d->name, ctx->name, sizeof(d->name)-1); d->name[sizeof(d->name)-1]='\0'; d->has_name=true; }
    if (ctx->has_flags) { d->flags=ctx->flags; d->has_flags=true; }
    if (ctx->has_ad_tx_power) { d->ad_tx_power=ctx->ad_tx_power; d->has_ad_tx_power=true; }
    if (ctx->has_appearance) { d->appearance=ctx->appearance; d->has_appearance=true; }
    for (uint8_t i=0;i<ctx->uuid16_count;i++) {
        uint16_t u=ctx->uuids16[i];
        if (!has_uuid16(d->uuids16,d->uuid16_count,u) && d->uuid16_count<MAX_UUID16) d->uuids16[d->uuid16_count++]=u;
    }
    if (ctx->has_mfr) { d->mfr_id=ctx->mfr_id; d->has_mfr=true; d->mfr_len=ctx->mfr_len; memcpy(d->mfr_data,ctx->mfr_data,ctx->mfr_len); }
    if (ctx->has_svc16) { d->svc16_uuid=ctx->svc16_uuid; d->has_svc16=true; d->svc16_len=ctx->svc16_len; memcpy(d->svc16_data,ctx->svc16_data,ctx->svc16_len); }
    d->has_fe9f |= ctx->has_fe9f;
    d->has_fcf1 |= ctx->has_fcf1;
}

static void print_hex_line(const char *prefix, const uint8_t *data, size_t len)
{
    printk("%s", prefix);
    for (size_t i=0;i<len;i++) printk("%02X%s", data[i], (i+1<len)?" ":"");
    printk("\n");
}

static void scan_recv(const struct bt_le_scan_recv_info *info, struct net_buf_simple *buf)
{
    struct ad_parse_ctx parsed = {0};
    int64_t now = k_uptime_get();
    uint8_t raw[MAX_RAW_DATA];
    uint8_t raw_len = MIN((size_t)buf->len, sizeof(raw));
    bool raw_truncated = buf->len > sizeof(raw);
    memcpy(raw, buf->data, raw_len);
    bt_data_parse(buf, ad_parse_cb, &parsed);

    k_mutex_lock(&devices_lock, K_FOREVER);
    int idx=find_device_locked(info->addr);
    if (idx<0) idx=alloc_device_locked(info->addr);
    if (idx<0) { k_mutex_unlock(&devices_lock); return; }
    struct observed_device *d=&devices[idx];
    if (d->packet_count==0) { d->first_seen_ms=now; d->min_rssi=info->rssi; d->max_rssi=info->rssi; }
    d->last_seen_ms=now;
    d->last_rssi=info->rssi;
    d->min_rssi=MIN(d->min_rssi,info->rssi);
    d->max_rssi=MAX(d->max_rssi,info->rssi);
    d->rssi_sum += info->rssi;
    d->packet_count++;
    bool is_scan_rsp=(info->adv_type==BT_GAP_ADV_TYPE_SCAN_RSP) || ((info->adv_props & BT_GAP_ADV_PROP_SCAN_RESPONSE)!=0);
    if (is_scan_rsp) d->scan_rsp_count++;
    else {
        d->adv_count++;
        if (d->last_adv_ms) { int64_t delta=now-d->last_adv_ms; if (delta>0 && delta<60000) { d->cadence_sum_ms += (uint64_t)delta; d->cadence_samples++; } }
        d->last_adv_ms=now;
    }
    d->last_adv_type=info->adv_type;
    d->last_adv_props=info->adv_props;
    d->last_primary_phy=info->primary_phy;
    d->last_secondary_phy=info->secondary_phy;
    if (info->tx_power!=BT_GAP_TX_POWER_INVALID) { d->controller_tx_power=info->tx_power; d->has_controller_tx_power=true; }
    d->raw_len=raw_len;
    d->raw_truncated=raw_truncated;
    memcpy(d->raw,raw,raw_len);
    merge_parsed_ad(d,&parsed);
    bool do_live=live_enabled && idx==selected_index && info->rssi>=display_rssi_floor;
    char live_addr[BT_ADDR_LE_STR_LEN];
    strncpy(live_addr,d->addr_str,sizeof(live_addr)-1); live_addr[sizeof(live_addr)-1]='\0';
    int live_rssi=d->last_rssi;
    uint8_t live_type=d->last_adv_type;
    bool live_fe9f=d->has_fe9f, live_fcf1=d->has_fcf1, live_google=d->has_mfr && d->mfr_id==0x00E0;
    k_mutex_unlock(&devices_lock);
    if (do_live) {
        printk("[LIVE #%d] %s RSSI=%d %s%s%s%s\n",idx,live_addr,live_rssi,adv_type_str(live_type),live_google?" GOOGLE":"",live_fe9f?" FE9F":"",live_fcf1?" FCF1":"");
        if (live_raw) print_hex_line("  RAW: ",raw,raw_len);
    }
}

static struct bt_le_scan_cb scan_callbacks={.recv=scan_recv};

static int scan_start_current(void)
{
    struct bt_le_scan_param param={
        .type=active_scan?BT_LE_SCAN_TYPE_ACTIVE:BT_LE_SCAN_TYPE_PASSIVE,
        .options=BT_LE_SCAN_OPT_NONE,
        .interval=BT_GAP_SCAN_FAST_INTERVAL_MIN,
        .window=BT_GAP_SCAN_FAST_WINDOW,
        .timeout=0,
        .interval_coded=0,
        .window_coded=0,
    };
    int err=bt_le_scan_start(&param,NULL);
    if (!err) scanning=true;
    return err;
}

static int scan_stop_current(void)
{
    int err=bt_le_scan_stop();
    if (!err || err==-EALREADY) { scanning=false; return 0; }
    return err;
}

static int scan_restart(void)
{
    (void)scan_stop_current();
    k_sleep(K_MSEC(50));
    return scan_start_current();
}

static int used_count_locked(void)
{
    int n=0; for (int i=0;i<MAX_DEVICES;i++) if (devices[i].used) n++; return n;
}

static void shell_print_hex(const struct shell *sh,const char *label,const uint8_t *data,size_t len)
{
    char line[(MAX_RAW_DATA*3)+32]; size_t pos=0;
    pos += snprintk(line+pos,sizeof(line)-pos,"%s",label);
    for (size_t i=0;i<len && pos+4<sizeof(line);i++) {
        pos += snprintk(line+pos,sizeof(line)-pos,"%02X",data[i]);
        if (i+1<len) { line[pos++]=' '; line[pos]='\0'; }
    }
    shell_print(sh,"%s",line);
}

static int cmd_status(const struct shell *sh,size_t argc,char **argv)
{
    ARG_UNUSED(argc); ARG_UNUSED(argv);
    k_mutex_lock(&devices_lock,K_FOREVER); int count=used_count_locked(); k_mutex_unlock(&devices_lock);
    shell_print(sh,"BLE Recon Interactive");
    shell_print(sh,"  scan:       %s",scanning?(active_scan?"ACTIVE":"PASSIVE"):"OFF");
    shell_print(sh,"  devices:    %d / %d",count,MAX_DEVICES);
    shell_print(sh,"  selected:   %d",selected_index);
    shell_print(sh,"  live:       %s",live_enabled?"ON":"OFF");
    shell_print(sh,"  raw live:   %s",live_raw?"ON":"OFF");
    shell_print(sh,"  RSSI floor: %d dBm",display_rssi_floor);
    return 0;
}

static int cmd_list(const struct shell *sh,size_t argc,char **argv)
{
    int floor=display_rssi_floor;
    if (argc>=2) { floor=strtol(argv[1],NULL,10); floor=CLAMP(floor,-127,20); }
    k_mutex_lock(&devices_lock,K_FOREVER);
    shell_print(sh,"Idx RSSI Avg  Pkts Age(s) Address                  Class     Type      Name/Tags");
    shell_print(sh,"--- ---- ---- ----- ------ ------------------------ --------- --------- ----------------");
    int64_t now=k_uptime_get();
    for (int i=0;i<MAX_DEVICES;i++) {
        struct observed_device *d=&devices[i]; if (!d->used || d->last_rssi<floor) continue;
        int avg=d->packet_count?(int)(d->rssi_sum/d->packet_count):d->last_rssi;
        long long age=(long long)((now-d->last_seen_ms)/1000);
        char tags[72]={0}; size_t p=0;
        if (d->has_name) p+=snprintk(tags+p,sizeof(tags)-p,"%s",d->name);
        if (d->has_mfr && p+2<sizeof(tags)) p+=snprintk(tags+p,sizeof(tags)-p,"%sMFR:%s",p?" ":"",company_name(d->mfr_id));
        if (d->has_fe9f && p+7<sizeof(tags)) p+=snprintk(tags+p,sizeof(tags)-p,"%sFE9F",p?" ":"");
        if (d->has_fcf1 && p+7<sizeof(tags)) p+=snprintk(tags+p,sizeof(tags)-p,"%sFCF1",p?" ":"");
        shell_print(sh,"%3d %4d %4d %5u %6lld %-24s %-9s %-9s %s%s",i,d->last_rssi,avg,d->packet_count,age,d->addr_str,addr_class(&d->addr),adv_type_str(d->last_adv_type),(i==selected_index)?"* ":"",tags[0]?tags:"-");
    }
    k_mutex_unlock(&devices_lock); return 0;
}

static int cmd_select(const struct shell *sh,size_t argc,char **argv)
{
    if (argc<2) { shell_error(sh,"Usage: ble select <idx>"); return -EINVAL; }
    int idx=strtol(argv[1],NULL,10);
    if (idx<0 || idx>=MAX_DEVICES) { shell_error(sh,"Index must be 0..%d",MAX_DEVICES-1); return -EINVAL; }
    k_mutex_lock(&devices_lock,K_FOREVER); bool exists=devices[idx].used; k_mutex_unlock(&devices_lock);
    if (!exists) { shell_error(sh,"No device at index %d",idx); return -ENOENT; }
    selected_index=idx; shell_print(sh,"Selected #%d. Try: ble info  |  ble live on",idx); return 0;
}

static int cmd_info(const struct shell *sh,size_t argc,char **argv)
{
    int idx=selected_index; if (argc>=2) idx=strtol(argv[1],NULL,10);
    if (idx<0 || idx>=MAX_DEVICES) { shell_error(sh,"Choose a device first: ble select <idx> OR ble info <idx>"); return -EINVAL; }
    k_mutex_lock(&devices_lock,K_FOREVER);
    if (!devices[idx].used) { k_mutex_unlock(&devices_lock); shell_error(sh,"No device at index %d",idx); return -ENOENT; }
    struct observed_device d=devices[idx]; k_mutex_unlock(&devices_lock);
    int avg=d.packet_count?(int)(d.rssi_sum/d.packet_count):d.last_rssi;
    uint64_t cadence=d.cadence_samples?d.cadence_sum_ms/d.cadence_samples:0;
    int64_t now=k_uptime_get();
    shell_print(sh,"Device #%d%s",idx,idx==selected_index?" [SELECTED]":"");
    shell_print(sh,"  address:       %s",d.addr_str);
    shell_print(sh,"  address class: %s",addr_class(&d.addr));
    shell_print(sh,"  RSSI:          last %d / avg %d / min %d / max %d dBm",d.last_rssi,avg,d.min_rssi,d.max_rssi);
    shell_print(sh,"  packets:       %u total, %u adv, %u scan-rsp",d.packet_count,d.adv_count,d.scan_rsp_count);
    shell_print(sh,"  first seen:    %lld s ago",(long long)((now-d.first_seen_ms)/1000));
    shell_print(sh,"  last seen:     %lld ms ago",(long long)(now-d.last_seen_ms));
    if (cadence) shell_print(sh,"  adv cadence:   ~%llu ms (%u samples)",(unsigned long long)cadence,d.cadence_samples);
    else shell_print(sh,"  adv cadence:   not enough samples");
    shell_print(sh,"  last PDU:      %s (0x%02X)",adv_type_str(d.last_adv_type),d.last_adv_type);
    shell_print(sh,"  properties:    0x%04X%s%s%s%s",d.last_adv_props,(d.last_adv_props&BT_GAP_ADV_PROP_CONNECTABLE)?" CONNECTABLE":"",(d.last_adv_props&BT_GAP_ADV_PROP_SCANNABLE)?" SCANNABLE":"",(d.last_adv_props&BT_GAP_ADV_PROP_DIRECTED)?" DIRECTED":"",(d.last_adv_props&BT_GAP_ADV_PROP_SCAN_RESPONSE)?" SCAN_RSP":"");
    shell_print(sh,"  PHY:           primary=%s secondary=%s",phy_str(d.last_primary_phy),phy_str(d.last_secondary_phy));
    if (d.has_controller_tx_power) shell_print(sh,"  controller TX: %d dBm",d.controller_tx_power);
    if (d.has_ad_tx_power) shell_print(sh,"  AD TX power:   %d dBm",d.ad_tx_power);
    if (d.has_name) shell_print(sh,"  name:          %s",d.name);
    if (d.has_flags) shell_print(sh,"  flags:         0x%02X",d.flags);
    if (d.has_appearance) shell_print(sh,"  appearance:    0x%04X",d.appearance);
    if (d.uuid16_count) {
        char line[128]={0}; size_t p=0;
        for (uint8_t i=0;i<d.uuid16_count && p+8<sizeof(line);i++) p+=snprintk(line+p,sizeof(line)-p,"%s%04X",i?" ":"",d.uuids16[i]);
        shell_print(sh,"  UUID16:        %s",line);
    }
    if (d.has_svc16) { shell_print(sh,"  service data:  UUID 0x%04X (%u bytes)",d.svc16_uuid,d.svc16_len); shell_print_hex(sh,"    payload:     ",d.svc16_data,d.svc16_len); }
    if (d.has_mfr) { shell_print(sh,"  manufacturer:  0x%04X %s",d.mfr_id,company_name(d.mfr_id)); shell_print_hex(sh,"    payload:     ",d.mfr_data,d.mfr_len); }
    if (d.has_fe9f || d.has_fcf1 || (d.has_mfr && d.mfr_id==0x00E0)) {
        shell_print(sh,"  fingerprints:");
        if (d.has_fe9f) shell_print(sh,"    + Google service UUID FE9F");
        if (d.has_fcf1) shell_print(sh,"    + Google service UUID FCF1");
        if (d.has_mfr && d.mfr_id==0x00E0) shell_print(sh,"    + Google manufacturer ID 0x00E0");
        shell_print(sh,"    confidence: %s",(d.has_fe9f && d.has_mfr && d.mfr_id==0x00E0)?"HIGH Google-associated advertisement":"supporting indicator(s), not identity proof");
    }
    shell_print_hex(sh,"  last raw AD:   ",d.raw,d.raw_len);
    if (d.raw_truncated) shell_warn(sh,"  raw data was truncated to %d bytes",MAX_RAW_DATA);
    return 0;
}

static int cmd_live(const struct shell *sh,size_t argc,char **argv)
{
    if (argc<2) { shell_print(sh,"live=%s raw=%s selected=%d",live_enabled?"on":"off",live_raw?"on":"off",selected_index); return 0; }
    if (!strcmp(argv[1],"on")) { if (selected_index<0) { shell_error(sh,"Select a device first: ble select <idx>"); return -EINVAL; } live_enabled=true; }
    else if (!strcmp(argv[1],"off")) live_enabled=false;
    else { shell_error(sh,"Usage: ble live on|off"); return -EINVAL; }
    shell_print(sh,"Live selected-device output: %s",live_enabled?"ON":"OFF"); return 0;
}

static int cmd_raw(const struct shell *sh,size_t argc,char **argv)
{
    if (argc<2) { shell_print(sh,"raw live output=%s",live_raw?"on":"off"); return 0; }
    if (!strcmp(argv[1],"on")) live_raw=true;
    else if (!strcmp(argv[1],"off")) live_raw=false;
    else { shell_error(sh,"Usage: ble raw on|off"); return -EINVAL; }
    shell_print(sh,"Raw packet output during live mode: %s",live_raw?"ON":"OFF"); return 0;
}

static int cmd_scan(const struct shell *sh,size_t argc,char **argv)
{
    if (argc<2) { shell_print(sh,"scan=%s",scanning?(active_scan?"active":"passive"):"off"); return 0; }
    if (!strcmp(argv[1],"off")) { int err=scan_stop_current(); if (err) { shell_error(sh,"Scan stop failed: %d",err); return err; } shell_print(sh,"Scanning stopped."); return 0; }
    if (!strcmp(argv[1],"on")) { int err=scanning?0:scan_start_current(); if (err) { shell_error(sh,"Scan start failed: %d",err); return err; } shell_print(sh,"Scanning %s.",active_scan?"ACTIVE":"PASSIVE"); return 0; }
    if (!strcmp(argv[1],"active")) active_scan=true;
    else if (!strcmp(argv[1],"passive")) active_scan=false;
    else { shell_error(sh,"Usage: ble scan on|off|active|passive"); return -EINVAL; }
    int err=scan_restart(); if (err) { shell_error(sh,"Scan restart failed: %d",err); return err; }
    shell_print(sh,"Scanning restarted in %s mode.",active_scan?"ACTIVE (scan requests enabled)":"PASSIVE (receive only)"); return 0;
}

static int cmd_filter(const struct shell *sh,size_t argc,char **argv)
{
    if (argc<2) { shell_print(sh,"Display/live RSSI floor: %d dBm",display_rssi_floor); return 0; }
    int v=strtol(argv[1],NULL,10); if (v<-127 || v>20) { shell_error(sh,"RSSI must be between -127 and +20 dBm"); return -EINVAL; }
    display_rssi_floor=v; shell_print(sh,"RSSI floor set to %d dBm. Tracking still keeps weaker devices.",v); return 0;
}

static int cmd_clear(const struct shell *sh,size_t argc,char **argv)
{
    ARG_UNUSED(argc); ARG_UNUSED(argv);
    k_mutex_lock(&devices_lock,K_FOREVER); memset(devices,0,sizeof(devices)); k_mutex_unlock(&devices_lock);
    selected_index=-1; live_enabled=false; shell_print(sh,"Device table cleared."); return 0;
}

static int cmd_help2(const struct shell *sh,size_t argc,char **argv)
{
    ARG_UNUSED(argc); ARG_UNUSED(argv);
    shell_print(sh,"Quick workflow:");
    shell_print(sh,"  ble list                -> devices");
    shell_print(sh,"  ble list -70            -> only strong devices");
    shell_print(sh,"  ble select 3            -> select #3");
    shell_print(sh,"  ble info                -> full decoded record");
    shell_print(sh,"  ble live on             -> live selected-device events");
    shell_print(sh,"  ble raw on              -> add raw hex to live events");
    shell_print(sh,"  ble scan passive        -> receive-only scan");
    shell_print(sh,"  ble scan active         -> request scan responses");
    shell_print(sh,"  ble filter -80          -> list/live RSSI floor");
    shell_print(sh,"  ble clear               -> wipe observations");
    shell_print(sh,"Address: PUBLIC / STATIC / RPA / NRPA");
    return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_ble,
    SHELL_CMD(status,NULL,"Scanner status",cmd_status),
    SHELL_CMD_ARG(list,NULL,"List devices [optional RSSI floor]",cmd_list,1,1),
    SHELL_CMD_ARG(info,NULL,"Full device info [optional index]",cmd_info,1,1),
    SHELL_CMD_ARG(select,NULL,"Select device index",cmd_select,2,0),
    SHELL_CMD_ARG(live,NULL,"Live selected device: on|off",cmd_live,1,1),
    SHELL_CMD_ARG(raw,NULL,"Raw hex in live mode: on|off",cmd_raw,1,1),
    SHELL_CMD_ARG(scan,NULL,"Scan: on|off|active|passive",cmd_scan,1,1),
    SHELL_CMD_ARG(filter,NULL,"Set display/live RSSI floor",cmd_filter,1,1),
    SHELL_CMD(clear,NULL,"Clear device table",cmd_clear),
    SHELL_CMD(help2,NULL,"Quick command guide",cmd_help2),
    SHELL_SUBCMD_SET_END
);
SHELL_CMD_REGISTER(ble,&sub_ble,"Interactive BLE observation/diagnostic scanner",NULL);

int main(void)
{
    printk("\n========================================\n");
    printk(" BLE Recon Interactive - nice!nano\n");
    printk("========================================\n");
    int err=bt_enable(NULL);
    if (err) { printk("Bluetooth init failed: %d\n",err); return 0; }
    bt_le_scan_cb_register(&scan_callbacks);
    err=scan_start_current();
    if (err) printk("Scan start failed: %d\n",err);
    else printk("Active scanning started.\n");
    printk("Type: ble help2\nThen: ble list\n\n");
    return 0;
}
