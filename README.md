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

ARP poruke se prenose unutar Ethernet okvira, pri čemu se u polju EtherType nalazi vrijednost `0x0806`, što označava da se u polju podataka (payload) nalazi ARP okvir. ARP okvir sadrži sljedeća ključna polja:

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

## ARP Paket

ARP paket se sastoji od Ethernet frame headera i ARP headera. Dužina Ethernet frame headera je 14 bajtova, dok je dužina ARP headera 28 bajtova. Informacije vezane za Address Resolution Protocol nalaze se upravo u ovom dijelu.
U ARP paketu, EtherType u Ethernet zaglavlju ima vrijednost 0x0806. Ostali dijelovi Ethernet headera isti su kao i kod drugih Ethernet paketa.
ARP header sadrži više različitih polja. Ispod se nalaze navedeni dijelovi ARP headera, jedan po jedan.
<img width="1131" height="582" alt="image" src="https://github.com/user-attachments/assets/bc90bd7e-3b97-43aa-a1e2-2c374282ac84" />

Kao što se može vidjeti u formatu ARP paketa, ARP header se sastoji od više različitih polja. Njihovi nazivi su:

- Hardware Type
- Protocol Type
- Hardware Address Length
- Protocol Address Length
- Operation Code
- Source MAC Address
- Source Protocol Address (IP)
- Target MAC Address
- Target Protocol Address (IP)



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


## FSM (Finite State Machine) dizajn
FSM dijagram je kreiran pomoću draw.io alata i sačuvan u fajlu `fsm_diagram.drawio`.
### Opis stanja FSM-a

1. **IDLE**: Početno stanje - modul čeka na početak novog paketa
   - `in_ready = '1'` - modul spreman za prijem
   - Prelaz u `RECEIVE_HEADER` kada je `in_valid = '1'` i `in_sop = '1'`

2. **RECEIVE_HEADER**: Prijem ARP header-a (prvih 8 bajtova)
   - Prijem prvih 8 bajtova ARP poruke
   - Prelaz u `RECEIVE_BODY` kada je `byte_counter >= 7`

3. **RECEIVE_BODY**: Prijem ARP body-a (preostalih 20 bajtova)
   - Prijem preostalih 20 bajtova ARP poruke
   - Prelaz u `CHECK_REQUEST` kada je `byte_counter >= 27`
   - Prelaz u `WAIT_EOP` ako je `in_eop = '1'` prije nego što je poruka kompletna

4. **CHECK_REQUEST**: Provjera da li je validan ARP Request
   - Provjera ARP header polja (Hardware Type, Protocol Type, itd.)
   - Provjera da li je Operation = Request (0x0001)
   - Provjera da li Target IP odgovara IP_ADDRESS parametru
   - Prelaz u `SEND_REPLY` ako je validan Request
   - Prelaz u `IDLE` ako nije validan Request

5. **SEND_REPLY**: Slanje ARP Reply poruke
   - Generisanje i slanje ARP Reply poruke (28 bajtova)
   - `out_sop = '1'` na početku paketa
   - `out_eop = '1'` na kraju paketa
   - Prelaz u `IDLE` kada je `reply_byte_counter = 27` i `out_ready = '1'`

6. **WAIT_EOP**: Čekanje na kraj paketa
   - Ako je paket završen prije nego što je primljeno 28 bajtova
   - Prelaz u `IDLE` kada je `in_eop = '1'.


## WaveDrom dijagram
Wavedrom dijagram je kreiran pomoću WaveDrom alata i prikazan je u fajlu `waveform.json`. Dijagrami pokrivaju sljedeće scenarije:
- **Ulazni signali**: Prijem ARP Request poruke (28 bajtova) kroz Avalon-ST interfejs
- **Izlazni signali**: Slanje ARP Reply poruke (28 bajtova) kroz Avalon-ST interfejs
- **Ready/Valid handshaking**: Pravilno rukovanje ready i valid signalima
- **SOP/EOP signali**: Označavanje početka i kraja paketa.

## VHDL implementacija

VHDL kod je implementiran u fajlu `arp_responder.vhd`. Modul implementira:



