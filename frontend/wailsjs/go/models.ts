export namespace config {
	
	export class Behavior {
	    enabled: boolean;
	    detect_dll_injection: boolean;
	    detect_process_injection: boolean;
	    detect_persistence: boolean;
	    detect_beaconing: boolean;
	    beacon_interval_max: number;
	    on_detect: string;
	
	    static createFrom(source: any = {}) {
	        return new Behavior(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.enabled = source["enabled"];
	        this.detect_dll_injection = source["detect_dll_injection"];
	        this.detect_process_injection = source["detect_process_injection"];
	        this.detect_persistence = source["detect_persistence"];
	        this.detect_beaconing = source["detect_beaconing"];
	        this.beacon_interval_max = source["beacon_interval_max"];
	        this.on_detect = source["on_detect"];
	    }
	}
	export class Notifications {
	    show_tray_on_threat: boolean;
	    show_toast: boolean;
	    play_sound: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Notifications(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.show_tray_on_threat = source["show_tray_on_threat"];
	        this.show_toast = source["show_toast"];
	        this.play_sound = source["play_sound"];
	    }
	}
	export class Quarantine {
	    path: string;
	    max_size_mb: number;
	    max_age_days: number;
	    auto_purge: boolean;
	    encrypt: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Quarantine(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.path = source["path"];
	        this.max_size_mb = source["max_size_mb"];
	        this.max_age_days = source["max_age_days"];
	        this.auto_purge = source["auto_purge"];
	        this.encrypt = source["encrypt"];
	    }
	}
	export class TokenGuard {
	    enabled: boolean;
	    protect_steam: boolean;
	    protect_discord: boolean;
	    protect_browsers: boolean;
	    block_reads: boolean;
	    on_detect: string;
	    notify_only: boolean;
	
	    static createFrom(source: any = {}) {
	        return new TokenGuard(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.enabled = source["enabled"];
	        this.protect_steam = source["protect_steam"];
	        this.protect_discord = source["protect_discord"];
	        this.protect_browsers = source["protect_browsers"];
	        this.block_reads = source["block_reads"];
	        this.on_detect = source["on_detect"];
	        this.notify_only = source["notify_only"];
	    }
	}
	export class RealTime {
	    enabled: boolean;
	    monitor_new_files: boolean;
	    monitor_processes: boolean;
	    monitor_handles: boolean;
	    monitor_registry: boolean;
	    monitor_network: boolean;
	    alert_verbosity: string;
	    on_token_theft: string;
	    on_malware: string;
	    on_suspicious: string;
	    on_beaconing: string;
	    scan_downloads: boolean;
	    scan_temp: boolean;
	
	    static createFrom(source: any = {}) {
	        return new RealTime(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.enabled = source["enabled"];
	        this.monitor_new_files = source["monitor_new_files"];
	        this.monitor_processes = source["monitor_processes"];
	        this.monitor_handles = source["monitor_handles"];
	        this.monitor_registry = source["monitor_registry"];
	        this.monitor_network = source["monitor_network"];
	        this.alert_verbosity = source["alert_verbosity"];
	        this.on_token_theft = source["on_token_theft"];
	        this.on_malware = source["on_malware"];
	        this.on_suspicious = source["on_suspicious"];
	        this.on_beaconing = source["on_beaconing"];
	        this.scan_downloads = source["scan_downloads"];
	        this.scan_temp = source["scan_temp"];
	    }
	}
	export class General {
	    install_path: string;
	    data_path: string;
	    log_level: string;
	    start_on_boot: boolean;
	    send_anonymized_stats: boolean;
	
	    static createFrom(source: any = {}) {
	        return new General(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.install_path = source["install_path"];
	        this.data_path = source["data_path"];
	        this.log_level = source["log_level"];
	        this.start_on_boot = source["start_on_boot"];
	        this.send_anonymized_stats = source["send_anonymized_stats"];
	    }
	}
	export class Config {
	    general: General;
	    real_time: RealTime;
	    token_guard: TokenGuard;
	    behavior: Behavior;
	    quarantine: Quarantine;
	    notifications: Notifications;
	    whitelist: string[];
	    whitelist_domains: string[];
	    exclusions: string[];
	    theme: string;
	    language: string;
	    hide_in_tray: boolean;
	    schema: number;
	
	    static createFrom(source: any = {}) {
	        return new Config(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.general = this.convertValues(source["general"], General);
	        this.real_time = this.convertValues(source["real_time"], RealTime);
	        this.token_guard = this.convertValues(source["token_guard"], TokenGuard);
	        this.behavior = this.convertValues(source["behavior"], Behavior);
	        this.quarantine = this.convertValues(source["quarantine"], Quarantine);
	        this.notifications = this.convertValues(source["notifications"], Notifications);
	        this.whitelist = source["whitelist"];
	        this.whitelist_domains = source["whitelist_domains"];
	        this.exclusions = source["exclusions"];
	        this.theme = source["theme"];
	        this.language = source["language"];
	        this.hide_in_tray = source["hide_in_tray"];
	        this.schema = source["schema"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	
	
	

}

export namespace events {
	
	export class Status {
	    real_time_active: boolean;
	    signature_count: number;
	    signature_version: string;
	    monitors: string[];
	    threats_today: number;
	    threats_blocked: number;
	    // Go type: time
	    last_scan: any;
	    // Go type: time
	    started_at: any;
	    db_path: string;
	    quarantine_count: number;
	    whitelisted: number;
	    wsc_registered: boolean;
	    drives?: string[];
	
	    static createFrom(source: any = {}) {
	        return new Status(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.real_time_active = source["real_time_active"];
	        this.signature_count = source["signature_count"];
	        this.signature_version = source["signature_version"];
	        this.monitors = source["monitors"];
	        this.threats_today = source["threats_today"];
	        this.threats_blocked = source["threats_blocked"];
	        this.last_scan = this.convertValues(source["last_scan"], null);
	        this.started_at = this.convertValues(source["started_at"], null);
	        this.db_path = source["db_path"];
	        this.quarantine_count = source["quarantine_count"];
	        this.whitelisted = source["whitelisted"];
	        this.wsc_registered = source["wsc_registered"];
	        this.drives = source["drives"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

