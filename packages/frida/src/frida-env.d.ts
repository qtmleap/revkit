// Frida ObjC bridge type declarations
declare namespace ObjC {
    const available: boolean;
    const classes: Record<string, any>;
    function Object(handle: any): any;
    class Block {
        constructor(handle: any);
        implementation: any;
    }
}

// Frida Java bridge type declarations
declare namespace Java {
    function perform(fn: () => void): void;
    function use(className: string): any;
    function registerClass(spec: any): any;
}

// Frida ApiResolver
declare class ApiResolver {
    constructor(type: string);
    enumerateMatches(query: string): Array<{ name: string; address: NativePointer }>;
}
