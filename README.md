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
4. Pošiljalac ažurira svoju ARP tabelu, upisuje par (IP, MAC) i omogućava slanje IP paketa ka tom odredištu koristeći dobijenu MAC adresu.

Na ovaj način ARP obezbjeđuje osnovnu funkcionalnost mapiranja IP → MAC u lokalnoj mreži, bez koje IPv4 saobraćaj ne bi mogao biti isporučen na podatkovnom nivou.

## ARP protokol

ARP paket se sastoji od Ethernet frame headera i ARP headera. Dužina Ethernet frame headera je 14 bajtova, dok je dužina ARP headera 28 bajtova. Informacije vezane za Address Resolution Protocol nalaze se upravo u ovom dijelu.
U ARP paketu, EtherType u Ethernet zaglavlju ima vrijednost 0x0806. Ostali dijelovi Ethernet headera isti su kao i kod drugih Ethernet paketa.
ARP header sadrži više različitih polja. Ispod se nalaze navedeni dijelovi ARP headera, jedan po jedan.
<img width="1131" height="582" alt="image" src="https://github.com/user-attachments/assets/bc90bd7e-3b97-43aa-a1e2-2c374282ac84" />

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
- **Target protocol address (TPA)** – IP adresa odredišta čija se MAC adresa traži.

Kombinacijom ovih polja, ARP omogućava da čvor jednoznačno identifikuje ko traži adresu (sender) i za koju IP adresu (target) želi da dobije MAC adresu.
Na narednoj slici prikazan je proces ARP komunikacije, uključujući ARP request i ARP reply:
<img width="987" height="799" alt="image" src="https://github.com/user-attachments/assets/bd80100d-f5b2-4fc2-bf94-2921d3f7d430" />



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

### **1. Testiranje reset stanja**

Testbench na početku drži `reset = '1'` tijekom 5 ciklusa, čime se provjerava ulazak modula u početno stanje. Nakon toga reset se spušta na `0`, što omogućuje testiranje pravilnog izlaska iz reset faze.

**Scenarij:** *Može li ARP responder ispravno startati i biti spreman primiti podatke nakon reseta?*


### **2. Slanje kompletnog ARP request okvira byte-po-byte**

Simulira se stvarni protok ARP paketa preko ulaznog streaming sučelja.
Svaki bajt okvira šalje se u jednom taktu:

* `in_sop = '1'` samo na prvom bajtu (početak paketa)
* `in_eop = '1'` samo na zadnjem bajtu (kraj paketa)

ARP request u testu sadržava:

* broadcast MAC destinaciju
* EtherType `0x0806`
* ARP operation = request
* target IP = **192.168.1.1** (IP adresa modula)

**Scenarij:** *Prepoznaje li modul ARP request koji je namijenjen njegovoj IP adresi?*


### **3. Testiranje `in_ready` handshake-a**

Iako testbench aktivno ne mijenja `in_ready`, očekuje se da modul ispravno upravlja handshake signalima i da nema zastoja u prijemu podataka.

**Scenarij:** *Može li modul prihvatiti ulazne podatke bez stalla?*

### **4. Očekivanje generisanja ARP reply okvira**

Nakon što se kompletan ARP request pošalje, simulacija čeka još 100 ciklusa kako bi se omogućilo generisanje odgovora.

Očekivani elementi ARP odgovora:

* `out_sop = '1'` na početku odgovora
* ispravno formiran ARP reply s ispravnim MAC i IP poljima
* `out_valid = '1'` tijekom slanja svih bajtova
* `out_eop = '1'` na posljednjem bajtu

**Scenarij:** *Generira li modul ispravan ARP odgovor?*


### **5. Pasivni scenarij čekanja**

Nakon slanja ulaznog paketa, testbench ne šalje ništa dalje, čime se provjerava stabilnost dizajna.

**Scenarij:** *Ostaje li modul stabilan nakon obrade paketa i bez dodatnog inputa?*



## WaveDrom dijagram
Wavedrom dijagram je kreiran pomoću WaveDrom alata i prikazan je u fajlu `waveform.json`. Dijagrami pokrivaju sljedeće scenarije:

## FSM (Finite State Machine) dizajn
FSM dijagram je kreiran pomoću draw.io alata i sačuvan u fajlu `fsm_diagram.drawio`.

### Opis stanja FSM-a


## VHDL implementacija

VHDL kod je implementiran u fajlu `arp_responder.vhd`. Modul implementira:

## Verifikacija pomoću simulacijskog alata ModelSim

## Zaključak

## Literatura

1. **Intel**. *Avalon Interface Specification, Intel Quartus Prime Design Suite 20.1*, v2022.01.24.  
   
2. **Spurgeon, Charles E.**, **Zimmerman, Joann**. *Ethernet: The Definitive Guide: Designing and Managing Local Area Networks*. 2nd ed. O'Reilly, 2025.

3. **Medhi, Deepankar**, **Ramasamy, Karthikeyan**. *Network Routing: Algorithms, Protocols, and Architectures*. Morgan Kaufmann, 2007. (Includes CD-ROM).
4. [ResearchGate: ARP Spoofing Solutions](https://www.researchgate.net/publication/276282183_Various_Solutions_for_Address_Resolution_Protocol_Spoofing_Attacks)
5. [Fortinet: What is ARP?](https://www.fortinet.com/resources/cyberglossary/what-is-arp)







