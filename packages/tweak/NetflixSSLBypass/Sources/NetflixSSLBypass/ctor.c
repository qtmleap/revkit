// Orion の constructor が呼ばれない場合のフォールバック
// __attribute__((constructor)) で dylib ロード時に確実に実行

extern void NetflixSSLBypass_constructor(void);

__attribute__((constructor))
static void _nfxbypass_ctor(void) {
    NetflixSSLBypass_constructor();
}
