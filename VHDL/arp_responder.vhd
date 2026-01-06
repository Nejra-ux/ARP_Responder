LIBRARY ieee;
USE ieee.std_logic_1164.ALL;
USE ieee.numeric_std.ALL;

-- ============================================================================
--  ARP RESPONDER (ETHERNET + ARP, 42 BAJTA: 14 + 28)
--  FSM: IDLE -> RX_ETH_HDR -> RX_ARP_FIELDS -> RX_ARP_ADDRS -> (TX_SEND ili DROP)
--
--  Provjere:
--    * EtherType = 0x0806
--    * ARP: HTYPE=0001, PTYPE=0800, HLEN=6, PLEN=4, OPER=0001 (REQUEST)
--    * TPA = IP_ADDRESS
--
--  Reply:
--    * OPER=0002, SHA/SPA = MAC_ADDRESS/IP_ADDRESS
--    * THA/TPA = SHA/SPA iz zahtjeva
--
--  Napomena:
--    * rx_idx poravnava da SOP bajt bude tretiran kao index=0 u ISTOM taktu
--    * Preuranjeni EOP (kratak okvir) -> povratak u IDLE (bez odgovora)
--    * Predugačak okvir (nema EOP na bajtu 41) -> DROP do EOP
-- ============================================================================

ENTITY arp_responder IS
  GENERIC (
    IP_ADDRESS  : STD_LOGIC_VECTOR(31 DOWNTO 0) := x"C0A80101"; -- 192.168.1.1
    MAC_ADDRESS : STD_LOGIC_VECTOR(47 DOWNTO 0) := x"02AABBCCDDEE"
  );
  PORT (
    clk   : IN  STD_LOGIC;
    reset : IN  STD_LOGIC;  -- AKTIVNO '1'

    -- Avalon-ST ulaz
    in_ready : OUT STD_LOGIC;
    in_valid : IN  STD_LOGIC;
    in_data  : IN  STD_LOGIC_VECTOR(7 DOWNTO 0);
    in_sop   : IN  STD_LOGIC;
    in_eop   : IN  STD_LOGIC;

    -- Avalon-ST izlaz
    out_ready : IN  STD_LOGIC;
    out_valid : OUT STD_LOGIC;
    out_data  : OUT STD_LOGIC_VECTOR(7 DOWNTO 0);
    out_sop   : OUT STD_LOGIC;
    out_eop   : OUT STD_LOGIC
  );
END ENTITY;

ARCHITECTURE rtl OF arp_responder IS

  TYPE state_t IS (IDLE, RX_ETH_HDR, RX_ARP_FIELDS, RX_ARP_ADDRS, DROP, TX_SEND);

  SIGNAL pr_state, nx_state : state_t := IDLE;

  -- Brojač bajta (RX i TX)
  SIGNAL byte_index : UNSIGNED(7 DOWNTO 0) := (OTHERS => '0');

  -- Indikatori greške 
  SIGNAL eth_fail        : STD_LOGIC := '0';
  SIGNAL arp_fields_fail : STD_LOGIC := '0';
  SIGNAL tpa_mismatch    : STD_LOGIC := '0';

  -- Sačuvani Requestor (iz ARP Request): SHA i SPA
  SIGNAL req_mac : STD_LOGIC_VECTOR(47 DOWNTO 0) := (OTHERS => '0');
  SIGNAL req_ip  : STD_LOGIC_VECTOR(31 DOWNTO 0) := (OTHERS => '0');

  -- Efektivni RX index (SOP bajt tretira kao 0 u istom ciklusu)
  SIGNAL rx_idx : INTEGER RANGE 0 TO 255;

  -- Greška na bajtu
  SIGNAL eth_fail_this        : STD_LOGIC;
  SIGNAL arp_fields_fail_this : STD_LOGIC;
  SIGNAL tpa_mismatch_this    : STD_LOGIC;

  -- Interni in_ready signal (OUT port se ne smije čitati)
  SIGNAL in_ready_i : STD_LOGIC;

  FUNCTION mac_byte(mac : STD_LOGIC_VECTOR(47 DOWNTO 0); b : INTEGER) RETURN STD_LOGIC_VECTOR IS
  BEGIN
    CASE b IS
      WHEN 0      => RETURN mac(47 DOWNTO 40);
      WHEN 1      => RETURN mac(39 DOWNTO 32);
      WHEN 2      => RETURN mac(31 DOWNTO 24);
      WHEN 3      => RETURN mac(23 DOWNTO 16);
      WHEN 4      => RETURN mac(15 DOWNTO 8);
      WHEN OTHERS => RETURN mac(7 DOWNTO 0);
    END CASE;
  END FUNCTION;

  FUNCTION ip_byte(ip : STD_LOGIC_VECTOR(31 DOWNTO 0); b : INTEGER) RETURN STD_LOGIC_VECTOR IS
  BEGIN
    CASE b IS
      WHEN 0      => RETURN ip(31 DOWNTO 24);
      WHEN 1      => RETURN ip(23 DOWNTO 16);
      WHEN 2      => RETURN ip(15 DOWNTO 8);
      WHEN OTHERS => RETURN ip(7 DOWNTO 0);
    END CASE;
  END FUNCTION;

BEGIN

  -- Ne prihvatamo novi okvir dok šaljemo reply 
  in_ready_i <= '0' WHEN pr_state = TX_SEND ELSE '1';
  in_ready   <= in_ready_i;

  -- Poravnanje, ako se prihvata SOP bajt, to je index 0
  rx_idx <= 0
    WHEN (in_valid='1' AND in_ready_i='1' AND in_sop='1')
    ELSE TO_INTEGER(byte_index);

  -- EtherType provjera (bajt 12..13 mora biti 08 06)
  eth_fail_this <= '1'
    WHEN (in_valid='1' AND in_ready_i='1' AND pr_state=RX_ETH_HDR AND
         ((rx_idx=12 AND in_data/=x"08") OR (rx_idx=13 AND in_data/=x"06")))
    ELSE '0';

  -- ARP fiksna polja + OPER=Request (bajt 14..21)
  arp_fields_fail_this <= '1'
    WHEN (in_valid='1' AND in_ready_i='1' AND pr_state=RX_ARP_FIELDS AND (
         (rx_idx=14 AND in_data/=x"00") OR
         (rx_idx=15 AND in_data/=x"01") OR
         (rx_idx=16 AND in_data/=x"08") OR
         (rx_idx=17 AND in_data/=x"00") OR
         (rx_idx=18 AND in_data/=x"06") OR
         (rx_idx=19 AND in_data/=x"04") OR
         (rx_idx=20 AND in_data/=x"00") OR
         (rx_idx=21 AND in_data/=x"01")
    ))
    ELSE '0';

  -- TPA provjera (bajt 38..41)
  tpa_mismatch_this <= '1'
    WHEN (in_valid='1' AND in_ready_i='1' AND pr_state=RX_ARP_ADDRS AND (
         (rx_idx=38 AND in_data/=ip_byte(IP_ADDRESS,0)) OR
         (rx_idx=39 AND in_data/=ip_byte(IP_ADDRESS,1)) OR
         (rx_idx=40 AND in_data/=ip_byte(IP_ADDRESS,2)) OR
         (rx_idx=41 AND in_data/=ip_byte(IP_ADDRESS,3))
    ))
    ELSE '0';

  -----------------------------------------------------------------------------
  -- NEXT STATE LOGIKA 
  -----------------------------------------------------------------------------
  PROCESS(pr_state, in_valid, in_sop, in_eop, out_ready, byte_index,
          eth_fail, arp_fields_fail, tpa_mismatch,
          eth_fail_this, arp_fields_fail_this, tpa_mismatch_this, rx_idx)
    VARIABLE eth_fail_n        : STD_LOGIC;
    VARIABLE arp_fields_fail_n : STD_LOGIC;
    VARIABLE tpa_mismatch_n    : STD_LOGIC;
  BEGIN
    nx_state <= pr_state;

    eth_fail_n        := eth_fail OR eth_fail_this;
    arp_fields_fail_n := arp_fields_fail OR arp_fields_fail_this;
    tpa_mismatch_n    := tpa_mismatch OR tpa_mismatch_this;

    CASE pr_state IS

      WHEN IDLE =>
        IF (in_valid='1' AND in_sop='1') THEN
          nx_state <= RX_ETH_HDR;
        ELSE
          nx_state <= IDLE;
        END IF;

      WHEN RX_ETH_HDR =>
        IF (in_valid='1' AND in_eop='1') THEN
          nx_state <= IDLE; -- kratak okvir
        ELSIF (in_valid='1' AND eth_fail_n='1') THEN
          nx_state <= DROP;
        ELSIF (in_valid='1' AND in_eop='0' AND rx_idx=13 AND eth_fail_n='0') THEN
          nx_state <= RX_ARP_FIELDS;
        ELSE
          nx_state <= RX_ETH_HDR;
        END IF;

      WHEN RX_ARP_FIELDS =>
        IF (in_valid='1' AND in_eop='1') THEN
          nx_state <= IDLE; -- kratak okvir
        ELSIF (in_valid='1' AND arp_fields_fail_n='1') THEN
          nx_state <= DROP;
        ELSIF (in_valid='1' AND in_eop='0' AND rx_idx=21 AND arp_fields_fail_n='0') THEN
          nx_state <= RX_ARP_ADDRS;
        ELSE
          nx_state <= RX_ARP_FIELDS;
        END IF;

     WHEN RX_ARP_ADDRS =>
  IF (in_valid='1' AND in_ready_i='1') THEN

    -- mismatch bilo kad u 38..41 -> DROP
    IF (tpa_mismatch_n='1') THEN
      nx_state <= DROP;

    -- zadnji bajt (41): ako je EOP tu -> TX, ako nije -> predugačak -> DROP
    ELSIF (rx_idx=41) THEN
      IF (in_eop='1') THEN
        nx_state <= TX_SEND;
      ELSE
        nx_state <= DROP;
      END IF;

    -- ako EOP dođe prije 41 -> kratak okvir
    ELSIF (in_eop='1') THEN
      nx_state <= IDLE;

    ELSE
      nx_state <= RX_ARP_ADDRS;
    END IF;

  ELSE
    nx_state <= RX_ARP_ADDRS;
  END IF;

      WHEN DROP =>
        IF (in_valid='1' AND in_eop='1') THEN
          nx_state <= IDLE;
        ELSE
          nx_state <= DROP;
        END IF;

      WHEN TX_SEND =>
        IF (out_ready='1' AND TO_INTEGER(byte_index)=41) THEN
          nx_state <= IDLE;
        ELSE
          nx_state <= TX_SEND;
        END IF;

    END CASE;
  END PROCESS;

  -----------------------------------------------------------------------------
  -- SEKVENCIJALNI DIO: stanje, brojač, pamćenje SHA/SPA
  -----------------------------------------------------------------------------
  PROCESS(clk)
    VARIABLE idx : INTEGER;
  BEGIN
    IF RISING_EDGE(clk) THEN
      IF reset='1' THEN
        pr_state <= IDLE;
        byte_index <= (OTHERS => '0');

        eth_fail        <= '0';
        arp_fields_fail <= '0';
        tpa_mismatch    <= '0';

        req_mac <= (OTHERS => '0');
        req_ip  <= (OTHERS => '0');

      ELSE
        pr_state <= nx_state;

        -- Novi okvir (SOP): očisti indikatore i sačuvane adrese
        IF (in_valid='1' AND in_ready_i='1' AND in_sop='1') THEN
          eth_fail        <= '0';
          arp_fields_fail <= '0';
          tpa_mismatch    <= '0';
          req_mac <= (OTHERS => '0');
          req_ip  <= (OTHERS => '0');
        END IF;

        -- indikatori
        IF (eth_fail_this='1') THEN
          eth_fail <= '1';
        END IF;

        IF (arp_fields_fail_this='1') THEN
          arp_fields_fail <= '1';
        END IF;

        IF (tpa_mismatch_this='1') THEN
          tpa_mismatch <= '1';
        END IF;

        -- Sačuvaj SHA (22..27) i SPA (28..31) iz request-a
        IF (in_valid='1' AND in_ready_i='1' AND pr_state=RX_ARP_ADDRS) THEN
          idx := rx_idx;

          IF (idx >= 22 AND idx <= 27) THEN
            CASE idx IS
              WHEN 22 => req_mac(47 DOWNTO 40) <= in_data;
              WHEN 23 => req_mac(39 DOWNTO 32) <= in_data;
              WHEN 24 => req_mac(31 DOWNTO 24) <= in_data;
              WHEN 25 => req_mac(23 DOWNTO 16) <= in_data;
              WHEN 26 => req_mac(15 DOWNTO 8)  <= in_data;
              WHEN 27 => req_mac(7 DOWNTO 0)   <= in_data;
              WHEN OTHERS => NULL;
            END CASE;
          END IF;

          IF (idx >= 28 AND idx <= 31) THEN
            CASE idx IS
              WHEN 28 => req_ip(31 DOWNTO 24) <= in_data;
              WHEN 29 => req_ip(23 DOWNTO 16) <= in_data;
              WHEN 30 => req_ip(15 DOWNTO 8)  <= in_data;
              WHEN 31 => req_ip(7 DOWNTO 0)   <= in_data;
              WHEN OTHERS => NULL;
            END CASE;
          END IF;
        END IF;

        -- Brojač bajta
        IF (nx_state = TX_SEND AND pr_state /= TX_SEND) THEN
          byte_index <= (OTHERS => '0'); -- ulazak u TX

        ELSIF (pr_state = TX_SEND) THEN
          IF (out_ready='1') THEN
            IF (TO_INTEGER(byte_index)=41) THEN
              byte_index <= (OTHERS => '0');
            ELSE
              byte_index <= byte_index + 1;
            END IF;
          END IF;

        ELSE
          IF (in_valid='1' AND in_ready_i='1') THEN
            IF (in_sop='1') THEN
              byte_index <= TO_UNSIGNED(1, byte_index'LENGTH);
            ELSE
              byte_index <= byte_index + 1;
            END IF;
          END IF;

          IF (nx_state = IDLE AND pr_state /= IDLE) THEN
            byte_index <= (OTHERS => '0');
          END IF;
        END IF;

      END IF;
    END IF;
  END PROCESS;

  -----------------------------------------------------------------------------
  -- IZLAZNI SIGNALI 
  -----------------------------------------------------------------------------
  out_valid <= '1' WHEN pr_state = TX_SEND ELSE '0';
  out_sop   <= '1' WHEN (pr_state = TX_SEND AND TO_INTEGER(byte_index)=0)  ELSE '0';
  out_eop   <= '1' WHEN (pr_state = TX_SEND AND TO_INTEGER(byte_index)=41) ELSE '0';

  -----------------------------------------------------------------------------
  -- out_data: ARP Reply okvir (42 bajta)
  -----------------------------------------------------------------------------
  PROCESS(pr_state, byte_index, req_mac, req_ip)
    VARIABLE i : INTEGER;
  BEGIN
    out_data <= (OTHERS => '0');

    IF pr_state = TX_SEND THEN
      i := TO_INTEGER(byte_index);

      CASE i IS
        -- Ethernet DST = req_mac
        WHEN 0  => out_data <= mac_byte(req_mac, 0);
        WHEN 1  => out_data <= mac_byte(req_mac, 1);
        WHEN 2  => out_data <= mac_byte(req_mac, 2);
        WHEN 3  => out_data <= mac_byte(req_mac, 3);
        WHEN 4  => out_data <= mac_byte(req_mac, 4);
        WHEN 5  => out_data <= mac_byte(req_mac, 5);

        -- Ethernet SRC = MAC_ADDRESS
        WHEN 6  => out_data <= mac_byte(MAC_ADDRESS, 0);
        WHEN 7  => out_data <= mac_byte(MAC_ADDRESS, 1);
        WHEN 8  => out_data <= mac_byte(MAC_ADDRESS, 2);
        WHEN 9  => out_data <= mac_byte(MAC_ADDRESS, 3);
        WHEN 10 => out_data <= mac_byte(MAC_ADDRESS, 4);
        WHEN 11 => out_data <= mac_byte(MAC_ADDRESS, 5);

        -- EtherType 0806
        WHEN 12 => out_data <= x"08";
        WHEN 13 => out_data <= x"06";

        -- ARP header + OPER=0002
        WHEN 14 => out_data <= x"00";
        WHEN 15 => out_data <= x"01";
        WHEN 16 => out_data <= x"08";
        WHEN 17 => out_data <= x"00";
        WHEN 18 => out_data <= x"06";
        WHEN 19 => out_data <= x"04";
        WHEN 20 => out_data <= x"00";
        WHEN 21 => out_data <= x"02";

        -- SHA = MAC_ADDRESS
        WHEN 22 => out_data <= mac_byte(MAC_ADDRESS, 0);
        WHEN 23 => out_data <= mac_byte(MAC_ADDRESS, 1);
        WHEN 24 => out_data <= mac_byte(MAC_ADDRESS, 2);
        WHEN 25 => out_data <= mac_byte(MAC_ADDRESS, 3);
        WHEN 26 => out_data <= mac_byte(MAC_ADDRESS, 4);
        WHEN 27 => out_data <= mac_byte(MAC_ADDRESS, 5);

        -- SPA = IP_ADDRESS
        WHEN 28 => out_data <= ip_byte(IP_ADDRESS, 0);
        WHEN 29 => out_data <= ip_byte(IP_ADDRESS, 1);
        WHEN 30 => out_data <= ip_byte(IP_ADDRESS, 2);
        WHEN 31 => out_data <= ip_byte(IP_ADDRESS, 3);

        -- THA = req_mac
        WHEN 32 => out_data <= mac_byte(req_mac, 0);
        WHEN 33 => out_data <= mac_byte(req_mac, 1);
        WHEN 34 => out_data <= mac_byte(req_mac, 2);
        WHEN 35 => out_data <= mac_byte(req_mac, 3);
        WHEN 36 => out_data <= mac_byte(req_mac, 4);
        WHEN 37 => out_data <= mac_byte(req_mac, 5);

        -- TPA = req_ip
        WHEN 38 => out_data <= ip_byte(req_ip, 0);
        WHEN 39 => out_data <= ip_byte(req_ip, 1);
        WHEN 40 => out_data <= ip_byte(req_ip, 2);
        WHEN 41 => out_data <= ip_byte(req_ip, 3);

        WHEN OTHERS =>
          out_data <= (OTHERS => '0');
      END CASE;
    END IF;
  END PROCESS;

END ARCHITECTURE;

