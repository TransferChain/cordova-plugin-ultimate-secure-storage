# TransferChain Secure Storage — geliştirici kılavuzu

**Sürüm:** 4.0.0. Android Keystore ve iOS Keychain üzerinde üç ayrı depolama
politikasını bir pakette sunar. Buradaki V1/V2/V3, npm paket sürümü değildir;
aynı plugin içindeki ayrı namespace ve erişim politikalarıdır.
[Kurulum ve kullanım](README.md).

## Kaynak haritası ve uygulama sınırı

| Dosya                                                  | Rol                                                |
| ------------------------------------------------------ | -------------------------------------------------- |
| [www/UltraSecureStorage.js](www/UltraSecureStorage.js) | Cordova Promise bridge ve action adları            |
| [Android Java](src/android/UltraSecureStorage.java)    | AES-GCM/Keystore, biometric prompt, native session |
| [iOS Swift](src/ios/UltraSecureStorage.swift)          | Keychain/LocalAuthentication, native session       |
| [plugin.xml](plugin.xml)                               | AndroidX Biometric, iOS izin metni, native kayıt   |

deviceready sonrasında window.UltraSecureStorage üzerinden çağırın. Plugin kendi
Promise bridge'ini ve native namespace'lerini sunar.

## V1, V2, V3 seçimi

| Politika | Veri koruması                   | Biyometrinin rolü     | Namespace |
| -------- | ------------------------------- | --------------------- | --------- |
| V1       | At-rest koruma                  | Yok                   | V1        |
| V2       | Biyometriye bağlı kayıt erişimi | Her secret read/write | V2        |
| V3       | At-rest koruma + native session | Oturumu açma          | V3        |

V1'de yazılan anahtar V2/V3'ten okunmaz. Erişim politikasını metot adıyla açıkça
seçin; biyometri başarısız olduğunda V1'e otomatik geçiş yapmayın.

```js
const storage = window.UltraSecureStorage

await storage.set('example-key', 'example-value')
await storage.setBiometric('protected-key', 'example-value', {
  reason: 'Authenticate to protect this value'
})
await storage.configureSession({ timeoutMs: 300000, lockOnBackground: true })
await storage.unlockSession({ reason: 'Unlock this session' })
try {
  await storage.setSession('session-key', 'example-value')
} finally {
  await storage.lockSession()
}
```

Örnek deviceready sonrasında çalışır. Gerçek secret değerleri loglamayın veya
uzun ömürlü state içinde tutmayın.

## Metotlar ve eksik kayıt davranışı

| Politika   | Metotlar                                                                  |
| ---------- | ------------------------------------------------------------------------- |
| V1         | set, get, has, remove, clear                                              |
| V2         | setBiometric, getBiometric, hasBiometric, removeBiometric, clearBiometric |
| V3         | setSession, getSession, hasSession, removeSession, clearSession           |
| Session    | configureSession, unlockSession, lockSession, sessionState                |
| Capability | biometricStatus                                                           |

Key boş olmayan string'dir; native üst sınır 1024'tür. Android String.length
UTF-16 birimi, iOS String.count karakter kümesi sayar; ASCII key adları iki
platformda aynı sınır davranışını verir. Unicode key sınırını değiştirirken
platformlar arası test ekleyin. Value string'dir; native üst sınır UTF-8 olarak
64 KiB'dir. Boş value geçerlidir. JSON gerekiyorsa uygulama serialize eder.
get/getBiometric/getSession eksik kayıtta NotFoundError('Key does not exists!')
ile reject eder; null dönmez. has boolean'dır. remove/clear, ilgili namespace
üzerinde yıkıcı işlemdir.

Bridge validation bazı hataları Promise oluşmadan senkron atabilir.
try/await/catch ile senkron doğrulama ve native rejection yollarını ele alın.
Eksik kayıtta code alanı NOT_FOUND string değeridir.

## Android veri yolu

V1/V2/V3 ayrı SharedPreferences adı ve Keystore alias'ı kullanır. AES-256-GCM,
her yazımda yeni IV ve türetilmiş storage key'e bağlı AAD vardır.
SharedPreferences'te plaintext value yerine sürümlü encrypted payload saklanır.
AAD kaydı başka mantıksal key altına kopyalama saldırısına karşı bağ kurar.

V2, biometricRequired Keystore key ve BiometricPrompt.CryptoObject(Cipher)
kullanır. Prompt başarılı olmadan ilgili cipher ile crypto işlem devam etmez.
Aynı anda ikinci prompt BIOMETRIC_BUSY ile reddedilir. AndroidX Biometric sürümü
plugin.xml'de 1.1.0'dır; key authorization ayarlarını değiştirirken API seviye
ayrımlarını koruyun.

V2 has/remove/clear plaintext açmaz ve prompt istemez. clearBiometric Android V2
alias'ını da siler; sonraki yazı yeni key oluşturur. Enrollment değişimiyle
geçersizleşmiş key'in verisini sessizce V1'e taşımayın.

## iOS veri yolu

V1 ve V3 Keychain accessibility: kSecAttrAccessibleWhenUnlockedThisDeviceOnly.

V2: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly + biometryCurrentSet. Bu
politika, cihaz passcode'u ve kayıtlı biyometri setiyle ilişkilidir. Keychain
service isimleri sürümleri ayırır. Keychain query veya access-control değişimi
veri erişimini kırabileceği için mevcut cihaz verisiyle migration planı olmadan
değiştirilmez. OSStatus sonuçları mevcut hata eşlemesine gider.

V3, V2'nin her işlemde crypto-bound biometric modelinin aynısı değildir. V3'te
native session kapısı açıldıktan sonra ayrı V3 deposu kullanılır.

## V3 yaşam döngüsü

configureSession varsayılanı 300.000 ms idle timeout; minimum 1.000 ms'dir.
lockOnBackground varsayılan true'dur. Mevcut kod, V3 depolama metodunda session
kontrolü geçtikten sonra, asıl storage işlemi başlamadan touchSession çağırır.
Dolayısıyla daha sonra başarısız olan bir storage isteği de idle zamanını
yenileyebilir; yalnızca başarılı commit'e bağlı bir süre değildir. sessionState
sorgusu idle süresini yenilemez. Oturum bilgisi native bellektedir; plaintext
kayıtların session cache'i yoktur.

Explicit lock, idle timeout, etkin background politikası, WebView reset ve
native lifecycle kapanışı oturumu kilitler. Process restart unlocked durumu geri
yüklemez. sessionState ekran gösterimi için snapshot'tır; authorization kararı
native storage metodunda yeniden uygulanır.

```mermaid
stateDiagram-v2
  [*] --> Locked
  Locked --> Unlocked: unlockSession + başarılı biyometri
  Unlocked --> Unlocked: session kontrolünden geçen V3 isteği
  Unlocked --> Locked: idle / background / lock / reset
  Locked --> Locked: V3 storage isteği SESSION_LOCKED
```

## Güvenli değişiklik örüntüsü

Yeni action eklerken bridge, Android execute switch, iOS selector ve plugin
testleri birlikte değiştirilir. get benzeri action'da eksik kayıt null değil
NOT_FOUND olmalıdır.

Cipher/AAD/payload version veya Keychain service değişikliğini sıradan refactor
saymayın. Eski kayıt okuma uyumluluğu, biyometri iptali, key invalidation ve
namespace izolasyonu test edilir. Kalıcı format değişiminde açık migration
gerekir; clear() çağırarak migration taklidi yapılmaz.

Hata ayıklarken yalnızca bilinen native code ve action bilgisi kullanılabilir.
Preference payload'ı, key, secret ve prompt sonucu ile ilgili hassas bilgi
loglanmaz. Bozuk ciphertext için otomatik key silme/veri kaybı uygulanmaz.

## Test ve doğrulama

[V1 cihaz yardımcısı](tests/js/secure-storage-tests.js),
[V2/V3 yardımcısı](tests/js/secure-storage-v2-v3-tests.js), Android ve iOS
platform testleri pakette bulunur. [TESTING](docs/TESTING.md) harness ve cihaz
gereksinimlerini açıklar. Yardımcılar namespace silebildiğinden yalnız ayrı test
kurulumunda kullanın.

Her namespace için CRUD, boş string, eksik get, biyometri iptali/enrollment, V3
idle/background/reset ve IV/AAD davranışı sınanmalıdır. Otomatik noninteractive
kontroller gerçek biyometrik kullanıcı akışlarının yerine geçmez.

## V3 revocation and pending biometric callbacks

A biometric prompt can finish after the application has locked or reset its
session. A successful result proves the earlier prompt succeeded; it does not
prove that its authorization request is still current.

Android captures sessionGeneration before opening the prompt. Revocation
increments that generation under the same monitor used by the private
completeSessionUnlock commit. A stale callback returns SESSION_LOCKED without
publishing unlocked state. A stale failure also cannot lock a newer generation.
The challenge and proof arrays are owned temporaries and are wiped after use.

iOS captures a UUID generation. lockSessionInternal replaces it; the LAContext
completion checks it before either success or failure changes state. This relies
on Cordova actions, lifecycle notifications and completion publication running
on the main queue. Moving V3 operations to background queues requires an
explicit synchronization design, not just copying the UUID check.

The Android noninteractive regression invokes the private completion guard with
a revoked generation only. It never injects successful authentication. This
verifies rejection at the real commit boundary, but does not replace real
biometric prompt/Keystore tests. Platform test code lives in tests/android and
tests/ios; see [verification instructions](docs/TESTING.md).
