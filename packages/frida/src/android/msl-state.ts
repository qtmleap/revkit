// Track current MSL request context for correlating crypto events
export let mslCurrentUrl: string | null = null;
export let mslCurrentDomain: string | null = null;

export function setMslContext(url: string | null, domain: string | null): void {
    mslCurrentUrl = url;
    mslCurrentDomain = domain;
}
