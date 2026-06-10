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

}

