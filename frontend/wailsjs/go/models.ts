export namespace main {

    export class LegacyStorageSelection {
        token: string;
        path: string;
        targetPath: string;

        static createFrom(source: any = {}) { return new LegacyStorageSelection(source); }

        constructor(source: any = {}) {
            if ('string' === typeof source) source = JSON.parse(source);
            this.token = source["token"];
            this.path = source["path"];
            this.targetPath = source["targetPath"];
        }
    }


	export class Account {
	    id: string;
	    title: string;
	    login: string;
	    password: string;
	    updatedAt: number;

	    static createFrom(source: any = {}) {
	        return new Account(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.title = source["title"];
	        this.login = source["login"];
	        this.password = source["password"];
	        this.updatedAt = source["updatedAt"];
	    }
	}
	export class TOTPSetup {
	    secret: string;
	    qrCode: string;

	    static createFrom(source: any = {}) {
	        return new TOTPSetup(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.secret = source["secret"];
	        this.qrCode = source["qrCode"];
	    }
	}
	export class VaultPublicStatus {
	    state: string;
	    v2ContainerPresent: boolean;
	    v2BackupPresent: boolean;
	    preparationFresh: boolean;

	    static createFrom(source: any = {}) {
	        return new VaultPublicStatus(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.state = source["state"];
	        this.v2ContainerPresent = source["v2ContainerPresent"];
	        this.v2BackupPresent = source["v2BackupPresent"];
	        this.preparationFresh = source["preparationFresh"];
	    }
	}
	export class StorageLocationStatus {
	    state: string;
	    path: string;
	    legacyPaths: Array<string>;
	    format: string;
	    algorithm: string;
	    backupPresent: boolean;
	    migrationPending: boolean;
	    temporaryFiles: number;
	    diagnostic: string;

	    static createFrom(source: any = {}) {
	        return new StorageLocationStatus(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.state = source["state"];
	        this.path = source["path"];
	        this.legacyPaths = source["legacyPaths"];
	        this.format = source["format"];
	        this.algorithm = source["algorithm"];
	        this.backupPresent = source["backupPresent"];
	        this.migrationPending = source["migrationPending"];
	        this.temporaryFiles = source["temporaryFiles"];
	        this.diagnostic = source["diagnostic"];
	    }
	}

}

