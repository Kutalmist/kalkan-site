# Kalkan site ve filtreler

- `index.html`, `privacy.html`: destek ve gizlilik sayfaları
- `filters/kalkan.txt`: Kalkan'a özel kurallar (Adblock Plus / AdGuard sözdizimi). Buraya eklenen kural ertesi gün tüm kullanıcılara ulaşır.
- `.github/workflows/filters.yml`: her gün ortak listeleri (EasyList, EasyPrivacy, AdGuard Mobil, AdGuard Çerez, AdGuard Base scriptlet'leri) ve 13 bölge paketini (Türkiye, Almanca, Fransızca, İspanyolca/Portekizce, İtalyanca, Felemenkçe, Lehçe, Rusça, Ukraynaca, Arapça, Japonca, Çince, Endonezce) `/filters/` altında yayınlar. Uygulama telefonun bölgesine göre ilgili paketi indirir.

Filtre lisansları: EasyList ailesi (EasyList, EasyPrivacy, EasyList Italy, EasyList Polish, Liste AR) CC BY-SA 3.0 + GPLv3 (https://easylist.to), AdGuard filtreleri GPLv3 (https://github.com/AdguardTeam/AdguardFilters), ABPindo GPLv3 (https://github.com/ABPindo/indonesianadblockrules). Çevrilmiş listeler aynı lisanslarla yayınlanır.
