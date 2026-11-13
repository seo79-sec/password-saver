export namespace main {

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
	    preparationFresh: boolean;

	    static createFrom(source: any = {}) {
	        return new VaultPublicStatus(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.state = source["state"];
	        this.v2ContainerPresent = source["v2ContainerPresent"];
	        this.preparationFresh = source["preparationFresh"];
	    }
	}

}

