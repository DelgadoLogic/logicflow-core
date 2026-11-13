using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace LogicFlow.Storage.Engine.Chunking;

/// <summary>
/// Precomputed Gear lookup tables for FastCDC 2020 two-byte rolling hash.
/// 256 high-entropy 64-bit entries fitting inside 2 KB L1 Data Cache.
/// Pinned permanently for zero-overhead unsafe pointer access.
/// </summary>
public static unsafe class GearTable
{
    public static readonly ulong[] Gear =
    [
        0x98379e436fbf0387UL, 0xefdf6874404097f4UL, 0x1f0e4fb73cf68cb2UL, 0xc7c9fc7df1c08044UL,
        0x327bf05bf869ee38UL, 0x22ce11a7db809f6aUL, 0x51ebc26d40026bd6UL, 0x56a42211e29e9619UL,
        0x564c76a5996720d2UL, 0x9fb4341aa9166f0bUL, 0x2506e6bf4ea61bb8UL, 0xc143de87ee5fb425UL,
        0xdf56ea365b2fd46aUL, 0xa5e40742f567b5f5UL, 0x47e1740924e3c50fUL, 0x1cf9bc77d94cfc62UL,
        0x011b988bb14a72d3UL, 0x93dc72be73fcb2baUL, 0xcb9b3ea83a48e785UL, 0x242484a0c8b36873UL,
        0x19dfa43a05ec5d6bUL, 0x59902636a04870f7UL, 0xb80092f6b47c6171UL, 0x3d07e6022e3914a1UL,
        0x10344d59a5ff3d94UL, 0x8fe7aa4b54e7d188UL, 0x3861cae2354c4149UL, 0x8e833ddca0cb9d75UL,
        0xd1d4fbf1d564fa2eUL, 0x7620bcfeefad3f6bUL, 0x8b43f9a7aa6a2eecUL, 0x6e760bf03e65ee77UL,
        0x2e0c5c4e7fb2fbdfUL, 0x838e55e24c291244UL, 0x1e367876a3ff1fd8UL, 0xbf552f416a41db3eUL,
        0x12a84a6c62c3e164UL, 0x1d4791557dcd5f75UL, 0xd986bf3ec7fa28e8UL, 0x651c6b5e0ee0c384UL,
        0x4523e1f579979727UL, 0x289762114ca84332UL, 0x3e10fa6580f48866UL, 0x5989182a472c2194UL,
        0x38dbb70bc906d445UL, 0x82f4d88e63080c55UL, 0x973a110a184128f7UL, 0x573426e9526ef04aUL,
        0x20359b3bb8752c03UL, 0xb8be34dcf01740fbUL, 0xdbcf384a22ad3178UL, 0x5ffb6bb984712efcUL,
        0xd2aa8be044e11c69UL, 0x5241775f0f3531fbUL, 0x7ab6a117d3d2dbbcUL, 0xb797ff1fa674ee6bUL,
        0x78ab16c827050e05UL, 0x2d174780517926b4UL, 0x718a22bc736a6cfbUL, 0x02179b8a9270df65UL,
        0xdd4b2a8d3e5e4544UL, 0x6280436a5c102b46UL, 0x364faee0e7e1781dUL, 0xaa2e1ff285499252UL,
        0x67dbdc1cbe8d2039UL, 0xd02ea9a0a0307044UL, 0x7f4e92eb8e2a3c7aUL, 0x497f47447db701bbUL,
        0x1927705141e6c310UL, 0x51c7a8292c306637UL, 0x1d582846cb46e297UL, 0x6436f56bc7f03529UL,
        0xa0a3a60a7e60d3e5UL, 0x61665a36341dffabUL, 0x3ac57f208173ea61UL, 0x32b508f7253cc52dUL,
        0x41ef710899451187UL, 0x8a927694f4c21a44UL, 0xd883e449fc6d6bf7UL, 0x1a86beeaeb03d526UL,
        0x7ee0a47d0ee9b692UL, 0xca1456209b5329cfUL, 0x6a0a09e057390ea1UL, 0xa1a9f140685938d2UL,
        0x8381bb53229b0f42UL, 0x51cf2644208a5c37UL, 0x00f3408092288339UL, 0x3d35c8e235fc5286UL,
        0x24749f7830cb0a62UL, 0x228795c6978436adUL, 0xa70146747e9ff8abUL, 0x2ecbaef9c2c2f689UL,
        0xc4e590f59c84e1b8UL, 0x6291a13e536100efUL, 0xa48d1a1b1a0d3174UL, 0x539bf4fc8f596856UL,
        0x6cfbba7d48386c99UL, 0x7e35b7194f4b16d1UL, 0x5011986422b406b2UL, 0x19f268f7fbe2b1a8UL,
        0x9fec9e289bf60a92UL, 0x63390c50d535ce98UL, 0xa3741829e2f074d6UL, 0x9334542289f666b6UL,
        0x4548cf09f0a2e7c4UL, 0xd029141029e06c11UL, 0x76b5a3bbcf009be4UL, 0x8a8fb0e0fa3b8ce4UL,
        0x56a644835698b671UL, 0x1c80c2f542456485UL, 0xc752a1290ee61bf4UL, 0x6a7bf528028ff798UL,
        0x19a0bc40428d02dfUL, 0x6961aa1852c92e76UL, 0x599ecfe565cf14e3UL, 0xb8e2501a3cf889d7UL,
        0x838ee591f09bb683UL, 0xb4a485fa6b31c6f4UL, 0xb79768a3c9e6bb05UL, 0x187ff27c6ee5144bUL,
        0x78abfe618f98ec44UL, 0x2287955c48b067d2UL, 0x70aa25cf0f2ff47eUL, 0xb8c01b1842b10be4UL,
        0x966c4c0bbca3c285UL, 0x6295ea3f40f06536UL, 0x573426e9526ef04aUL, 0x011b988bb14a72d3UL,
        0xdf56ea365b2fd46aUL, 0x8b43f9a7aa6a2eecUL, 0x19dfa43a05ec5d6bUL, 0xd1d4fbf1d564fa2eUL,
        0x2e0c5c4e7fb2fbdfUL, 0x12a84a6c62c3e164UL, 0x4523e1f579979727UL, 0x3e10fa6580f48866UL,
        0x38dbb70bc906d445UL, 0x973a110a184128f7UL, 0x20359b3bb8752c03UL, 0xdbcf384a22ad3178UL,
        0xd2aa8be044e11c69UL, 0x7ab6a117d3d2dbbcUL, 0x78ab16c827050e05UL, 0x718a22bc736a6cfbUL,
        0xdd4b2a8d3e5e4544UL, 0x364faee0e7e1781dUL, 0x67dbdc1cbe8d2039UL, 0x7f4e92eb8e2a3c7aUL,
        0x1927705141e6c310UL, 0x1d582846cb46e297UL, 0xa0a3a60a7e60d3e5UL, 0x3ac57f208173ea61UL,
        0x41ef710899451187UL, 0xd883e449fc6d6bf7UL, 0x7ee0a47d0ee9b692UL, 0x6a0a09e057390ea1UL,
        0x8381bb53229b0f42UL, 0x00f3408092288339UL, 0x24749f7830cb0a62UL, 0xa70146747e9ff8abUL,
        0xc4e590f59c84e1b8UL, 0xa48d1a1b1a0d3174UL, 0x6cfbba7d48386c99UL, 0x5011986422b406b2UL,
        0x9fec9e289bf60a92UL, 0xa3741829e2f074d6UL, 0x4548cf09f0a2e7c4UL, 0x76b5a3bbcf009be4UL,
        0x56a644835698b671UL, 0xc752a1290ee61bf4UL, 0x19a0bc40428d02dfUL, 0x599ecfe565cf14e3UL,
        0x838ee591f09bb683UL, 0xb79768a3c9e6bb05UL, 0x78abfe618f98ec44UL, 0x70aa25cf0f2ff47eUL,
        0x966c4c0bbca3c285UL, 0x51ebc26d40026bd6UL, 0x1f0e4fb73cf68cb2UL, 0x327bf05bf869ee38UL,
        0x564c76a5996720d2UL, 0x2506e6bf4ea61bb8UL, 0xdf56ea365b2fd46aUL, 0x47e1740924e3c50fUL,
        0x011b988bb14a72d3UL, 0xcb9b3ea83a48e785UL, 0x19dfa43a05ec5d6bUL, 0xb80092f6b47c6171UL,
        0x10344d59a5ff3d94UL, 0x3861cae2354c4149UL, 0xd1d4fbf1d564fa2eUL, 0x8b43f9a7aa6a2eecUL,
        0x2e0c5c4e7fb2fbdfUL, 0x1e367876a3ff1fd8UL, 0x12a84a6c62c3e164UL, 0xd986bf3ec7fa28e8UL,
        0x4523e1f579979727UL, 0x3e10fa6580f48866UL, 0x38dbb70bc906d445UL, 0x973a110a184128f7UL,
        0x20359b3bb8752c03UL, 0xdbcf384a22ad3178UL, 0xd2aa8be044e11c69UL, 0x7ab6a117d3d2dbbcUL,
        0x78ab16c827050e05UL, 0x718a22bc736a6cfbUL, 0xdd4b2a8d3e5e4544UL, 0x364faee0e7e1781dUL,
        0x67dbdc1cbe8d2039UL, 0x7f4e92eb8e2a3c7aUL, 0x1927705141e6c310UL, 0x1d582846cb46e297UL,
        0xa0a3a60a7e60d3e5UL, 0x3ac57f208173ea61UL, 0x41ef710899451187UL, 0xd883e449fc6d6bf7UL,
        0x7ee0a47d0ee9b692UL, 0x6a0a09e057390ea1UL, 0x8381bb53229b0f42UL, 0x00f3408092288339UL,
        0x24749f7830cb0a62UL, 0xa70146747e9ff8abUL, 0xc4e590f59c84e1b8UL, 0xa48d1a1b1a0d3174UL,
        0x6cfbba7d48386c99UL, 0x5011986422b406b2UL, 0x9fec9e289bf60a92UL, 0xa3741829e2f074d6UL,
        0x4548cf09f0a2e7c4UL, 0x76b5a3bbcf009be4UL, 0x56a644835698b671UL, 0xc752a1290ee61bf4UL,
        0x19a0bc40428d02dfUL, 0x599ecfe565cf14e3UL, 0x838ee591f09bb683UL, 0xb79768a3c9e6bb05UL,
        0x78abfe618f98ec44UL, 0x70aa25cf0f2ff47eUL, 0x966c4c0bbca3c285UL, 0xefdf6874404097f4UL,
        0xc7c9fc7df1c08044UL, 0x22ce11a7db809f6aUL, 0x56a42211e29e9619UL, 0x9fb4341aa9166f0bUL,
        0xc143de87ee5fb425UL, 0xa5e40742f567b5f5UL, 0x1cf9bc77d94cfc62UL, 0x93dc72be73fcb2baUL,
        0x242484a0c8b36873UL, 0x59902636a04870f7UL, 0x3d07e6022e3914a1UL, 0x8fe7aa4b54e7d188UL,
        0x8e833ddca0cb9d75UL, 0x7620bcfeefad3f6bUL, 0x6e760bf03e65ee77UL, 0x838e55e24c291244UL,
        0xbf552f416a41db3eUL, 0x1d4791557dcd5f75UL, 0x651c6b5e0ee0c384UL, 0x289762114ca84332UL,
        0x5989182a472c2194UL, 0x82f4d88e63080c55UL, 0x573426e9526ef04aUL, 0xb8be34dcf01740fbUL,
        0x5ffb6bb984712efcUL, 0x5241775f0f3531fbUL, 0xb797ff1fa674ee6bUL, 0x2d174780517926b4UL,
        0x02179b8a9270df65UL, 0x6280436a5c102b46UL, 0xaa2e1ff285499252UL, 0xd02ea9a0a0307044UL,
        0x497f47447db701bbUL, 0x51c7a8292c306637UL, 0x6436f56bc7f03529UL, 0x61665a36341dffabUL,
        0x32b508f7253cc52dUL, 0x8a927694f4c21a44UL, 0x1a86beeaeb03d526UL, 0xca1456209b5329cfUL,
        0xa1a9f140685938d2UL, 0x51cf2644208a5c37UL, 0x3d35c8e235fc5286UL, 0x228795c6978436adUL,
        0x2ecbaef9c2c2f689UL, 0x6291a13e536100efUL, 0x539bf4fc8f596856UL, 0x7e35b7194f4b16d1UL,
        0x19f268f7fbe2b1a8UL, 0x63390c50d535ce98UL, 0x9334542289f666b6UL, 0xd029141029e06c11UL,
        0x8a8fb0e0fa3b8ce4UL, 0x1c80c2f542456485UL, 0x6a7bf528028ff798UL, 0x6961aa1852c92e76UL,
        0xb8e2501a3cf889d7UL, 0xb4a485fa6b31c6f4UL, 0x187ff27c6ee5144bUL, 0x2287955c48b067d2UL,
        0xb8c01b1842b10be4UL, 0x6295ea3f40f06536UL, 0x327bf05bf869ee38UL, 0x9fb4341aa9166f0bUL
    ];

    public static readonly ulong[] GearLs = new ulong[256];

    private static readonly GCHandle s_gearHandle;
    private static readonly GCHandle s_gearLsHandle;

    public static readonly ulong* GearPtr;
    public static readonly ulong* GearLsPtr;

    static GearTable()
    {
        for (int i = 0; i < 256; i++)
        {
            GearLs[i] = Gear[i] << 1;
        }

        s_gearHandle = GCHandle.Alloc(Gear, GCHandleType.Pinned);
        GearPtr = (ulong*)s_gearHandle.AddrOfPinnedObject();

        s_gearLsHandle = GCHandle.Alloc(GearLs, GCHandleType.Pinned);
        GearLsPtr = (ulong*)s_gearLsHandle.AddrOfPinnedObject();
    }
}
