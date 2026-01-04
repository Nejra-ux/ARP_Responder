# ARP Responder

## Uvod

ARP (Address Resolution Protocol) je protokol koji povezuje logičko adresiranje na mrežnom sloju (IPv4 adrese) sa fizičkim adresiranjem na podatkovnom sloju (MAC adrese) u lokalnoj mreži. U tipičnoj Ethernet LAN mreži, Ethernet okvir se isporučuje na osnovu MAC adrese odredišta, dok aplikacije i protokoli viših slojeva (npr. TCP/UDP) komuniciraju korištenjem IP adresa.

Kada čvor želi poslati IP paket ka određenoj IPv4 adresi u istoj lokalnoj mreži, on mora znati kojoj MAC adresi ta IP adresa pripada. Ako tražena IP adresa nije prisutna u lokalnoj ARP tabeli (ARP cache), čvor inicira ARP postupak razrješenja adrese (engl. address resolution):

1. Generiše se ARP Request – broadcast Ethernet okvir u kojem se navodi:
   - IP adresa čvora čija se MAC adresa traži,
   - IP i MAC adresa pošiljaoca zahtjeva.
2. Svi uređaji u lokalnoj mreži primaju ARP Request, ali **odgovara samo onaj čija IP adresa odgovara traženoj adresi**.
3. Taj uređaj šalje ARP Reply – unicast Ethernet okvir koji sadrži:
   - svoju MAC adresu,
   - svoju IP adresu (kao potvrdu),
   - IP/MAC adrese pošiljaoca zahtjeva u odgovarajućim poljima.
4. Pošiljalac ažurira svoju ARP tabelu, upisuje par (IP, MAC) i omogućava slanje IP paketa ka tom odredištu koristeći dobijenu MAC adresu [1].

Na narednoj slici prikazan je proces ARP komunikacije, uključujući ARP request i ARP reply:

<p align="center">
<img width="600" height="500" alt="image" src="https://github.com/user-attachments/assets/bd80100d-f5b2-4fc2-bf94-2921d3f7d430" /><br>
  <em> Slika 1. Proces ARP komunikacije [1]</em>
</p>



## ARP protokol

ARP paket se sastoji od Ethernet frame headera i ARP headera. Dužina Ethernet frame headera je 14 bajtova, dok je dužina ARP headera 28 bajtova. Informacije vezane za Address Resolution Protocol nalaze se upravo u ovom dijelu.
U ARP paketu, EtherType u Ethernet zaglavlju ima vrijednost 0x0806 [2]. Ostali dijelovi Ethernet headera isti su kao i kod drugih Ethernet paketa.
ARP header sadrži više različitih polja. Ispod se nalaze navedeni dijelovi ARP headera, jedan po jedan.

<p align="center">
 <img width="900" height="500" alt="image" src="https://github.com/user-attachments/assets/bc90bd7e-3b97-43aa-a1e2-2c374282ac84" /><br>
  <em> Slika 2. Dijelovi ARP headera [3]</em>
</p>



Kao što se može vidjeti u formatu ARP paketa, ARP header se sastoji od više različitih polja. Njihovi nazivi su:


- **Hardware type (HTYPE)** – tip fizičkog interfejsa; za Ethernet je najčešće vrijednost `1`.
- **Protocol type (PTYPE)** – identifikator protokola višeg sloja; za IPv4 se koristi vrijednost `0x0800`.
- **Hardware address length (HLEN)** – dužina hardverske (MAC) adrese u oktetima; za Ethernet je `6`.
- **Protocol address length (PLEN)** – dužina IP adrese u oktetima; za IPv4 je `4`.
- **Opcode** – tip ARP poruke:
  - `1` – ARP Request,
  - `2` – ARP Reply.
- **Sender hardware address (SHA)** – MAC adresa pošiljaoca ARP poruke.
- **Sender protocol address (SPA)** – IP adresa pošiljaoca ARP poruke.
- **Target hardware address (THA)** – MAC adresa odredišta (kod ARP Requesta se često stavlja nula, jer još nije poznata).
- **Target protocol address (TPA)** – IP adresa odredišta čija se MAC adresa traži [3].

Kombinacijom ovih polja, ARP omogućava da čvor jednoznačno identifikuje ko traži adresu (sender) i za koju IP adresu (target) želi da dobije MAC adresu.

## Opis projekta i popis signala

U ovom projektu implementira se VHDL modul ARP Responder, čija je uloga da odgovori na ARP upite za rezoluciju MAC adrese lokalnog čvora. Modul prima Ethernet/ARP okvire putem Avalon-ST interfejsa i generiše odgovarajući ARP reply kada je ciljna IP adresa jednaka adresi konfigurisanog čvora.
IP adresa i MAC adresa uređaja definišu se kao generički parametri prilikom instanciranja modula, što omogućava jednostavnu integraciju u različite mrežne konfiguracije. Komunikacija preko ulaznih i izlaznih portova odvija se korištenjem ready/valid rukovanja, koje obezbjeđuje pouzdan prijenos podataka kroz tok.
U nastavku je prikazan popis svih signala korištenih u ARP Responder modulu: 
- `clock`: Takt signal
- `reset`: Reset signal (aktivna visoka vrednost)
- `in_data[7:0]`: Ulazni podaci (bajt po bajt)
- `in_valid`: Validnost ulaznih podataka
- `in_sop`: Start of Packet za ulaz
- `in_eop`: End of Packet za ulaz
- `in_ready`: Ready signal za ulaz (modul spreman za prijem)
- `out_data[7:0]`: Izlazni podaci (bajt po bajt)
- `out_valid`: Validnost izlaznih podataka
- `out_sop`: Start of Packet za izlaz
- `out_eop`: End of Packet za izlaz
- `out_ready`: Ready signal za izlaz (primalac spreman).

## Scenariji za testiranje

Validacija ARP Responder modula izvršena je kroz dva ključna scenarija koji pokrivaju ispravno procesiranje, filtriranje saobraćaja i ignorisanje nepodržanih protokola.

### **1. Validna ARP rezolucija (Target IP Match)**
Ovo je osnovni scenarij u kojem modul prima ARP zahtjev koji je namijenjen upravo njemu.

*   **Ulaz:** Testbench šalje broadcast **ARP Request** u kojem je `Target IP` jednak IP adresi modula (npr. `192.168.1.1`).
*   **Proces:** Modul detektuje ispravan `EtherType (0x0806)` i poklapanje IP adrese.
*   **Rezultat:** Modul generiše **ARP Reply** (unicast) sa svojom MAC adresom. Izlazni signal `out_valid` postaje aktivan.

<p align="center">
  <img src="Idejni%20koncepti/Scenarij_1.drawio.png" width="500"><br>
  <em>Slika 3: UML sekvencijalni dijagram – validna ARP rezolucija</em>
</p>


### **2. Filtriranje tuđih zahtjeva i nevažećeg saobraćaja (Target IP Mismatch)**

Ovaj scenarij izvršava provjeru  da li modul ispravno ignoriše ARP zahtjeve koji su namijenjeni drugim uređajima u mreži te testira robusnost dizajna na okvire koji nisu relevantni za ARP rezoluciju.
* **Ulaz:** Testbench generiše niz testnih vektora koji ne zadovoljavaju uslove za odgovor:
o	Target IP Mismatch: ARP Request sa ispravnim formatom, ali Target IP adresom koja ne pripada modulu (npr. `192.168.1.50`). 
o	Non-ARP: Ethernet okviri koji nisu ARP protokola (npr. IPv4 paket gdje je `EtherType = 0x0800`).
o	Invalid ARP Format/Opcode: ARP okviri koji nisu zahtjev za rezoluciju (`Opcode ≠ 0x0001`) ili imaju neispravne parametre zaglavlja (`HTYPE ≠ 0x0001`, `PTYPE ≠ 0x0800`, `HLEN ≠ 6`, `PLEN ≠ 4`). 
* **Proces:**  Modul vrši sekvencijalnu validaciju zaglavlja. Prvo provjerava EtherType, zatim ispravnost ARP parametara i Opcode polja, te konačno poredi Target IP adresu. Ukoliko bilo koji od ovih uslova nije zadovoljen (pogrešan protokol, neispravan format, pogrešan Opcode ili tuđa IP adresa), modul prekida dalju obradu.
* **Rezultat:**  Modul ignoriše paket (DROP) i ne generiše ARP Reply. Izlazna linija out_valid ostaje neaktivna ('0'), čime se potvrđuje da modul ispravno odbacuje sav saobraćaj koji ne zahtijeva njegovu intervenciju.
<p align="center">
  <img src="Idejni%20koncepti/Scenario 2 (2+3).drawio.png" width="600"><br>
  <em>Slika 4: UML sekvencijalni dijagram – Filtriranje tuđih zahtjeva i nevažećeg saobraćaja (Target IP Mismatch) </em>
</p>

## WaveDrom dijagram
Wavedrom dijagrami su kreirani pomoću WaveDrom alata. Izvorni `.json` fajlovi za sve prikazane scenarije dostupni su u direktoriju [Wavedrom](./Wavedrom).

Dijagrami pokrivaju sljedeće scenarije:

### Scenario 1: Validna ARP Rezolucija (Target IP Match)

Prikazani vremenski dijagram ilustruje rad modula kada primi validan ARP zahtjev (Request) namijenjen ovom uređaju.
<p align="center">
  <img src="Wavedrom/Scenarij_1.png" width="1000"><br>
  <em>Slika 5: Wavedrom za uspješnu rezoluciju </em>
</p>

*   **Ulazna faza (`RX_CHECK`):**
    *   Modul putem **Avalon-ST** interfejsa prima *broadcast* paket (vidljivo po `FF..FF` na `in_data`).
    *   Interna logika provjerava *Target IP* polje u paketu.
*   **Logika odlučivanja:**
    *   Detektovano je poklapanje ciljane IP adrese sa lokalnom adresom.
    *   Automat stanja prelazi iz `RX_CHECK` u `TX_CHECK`.
*   **Izlazna faza (`TX_CHECK`):**
    *   Modul generiše ARP odgovor (*Reply*).
    *   Na `out_data` liniji se šalje paket sa *unicast* MAC adresom pošiljaoca, potvrđujući rezoluciju adrese.

### Scenario 2: Nevalidna ARP Rezolucija (Target IP Mismatch)


Dijagram prikazuje ponašanje modula kada primi ARP zahtjev koji nije namijenjen ovom uređaju (nepoklapanje IP adrese).

<p align="center">
  <img src="Wavedrom/Scenarij_2.png" width="1000"><br>
  <em>Slika 6: Wavedrom za neuspješnu rezoluciju </em>
</p>

*   **Ulazna faza (`RX_CHECK`):** Modul uredno prima *broadcast* ARP paket putem **Avalon-ST input** interfejsa.
*   **Logika odlučivanja:** Tokom provjere sadržaja paketa, modul detektuje da se *Target IP* u zahtjevu **ne podudara** sa lokalnom IP adresom.
*   **Ishod (`DROP`):**
    *   Automat stanja prelazi u `DROP`, a zatim se vraća u `IDLE`.
    *   **Nema odgovora:** `AVALON-ST output` signali (`out_valid`, `out_sop`, itd.) ostaju na nuli, što znači da modul ne šalje nikakav odgovor na mrežu. 

## FSM (Finite State Machine) dizajn
FSM dijagram je kreiran pomoću draw.io alata i sačuvan u fajlu `fsm_diagram.drawio`.

### Opis stanja FSM-a


## VHDL implementacija

VHDL kod je implementiran u fajlu `arp_responder.vhd`. Modul implementira:

## Verifikacija pomoću simulacijskog alata ModelSim

## Zaključak

## Literatura

   
[1] **Spurgeon, Charles E.**, **Zimmerman, Joann**. *Ethernet: The Definitive Guide: Designing and Managing Local Area Networks*. 2nd ed. O'Reilly, 2025.

[2] **Medhi, Deepankar**, **Ramasamy, Karthikeyan**. *Network Routing: Algorithms, Protocols, and Architectures*. Morgan Kaufmann, 2007. (Includes CD-ROM).

[3] “Address Resolution Protocol (ARP),” IPCisco. [Online]. Available: https://ipcisco.com/lesson/address-resolution-protocol-arp/. 

[4] A. Author et al., “Various Solutions for Address Resolution Protocol Spoofing Attacks,” ResearchGate. [Online]. Available: https://www.researchgate.net/publication/276282183_Various_Solutions_for_Address_Resolution_Protocol_Spoofing_Attacks. 

[5] “What is ARP?,” Fortinet. [Online]. Available: https://www.fortinet.com/resources/cyberglossary/what-is-arp. 

[6] **Intel**. *Avalon Interface Specification, Intel Quartus Prime Design Suite 20.1*, v2022.01.24.  






