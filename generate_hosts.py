def generateTemplate(host_name, redirects):
  return f"""
    server {{
        listen 80;
        listen [::]:80;
        server_name {host_name};
        
        # Redirect to https
        location / {{
            rewrite ^(.*) https://{host_name}:443$1 permanent;
        }}    

        # letsencrypt
        location /.well-known/acme-challenge/ {{
            root /var/www/certbot;
        }}

        location /nginx_status {{
            stub_status;
            allow 127.0.0.1;	#only allow requests from localhost
            deny all;		#deny all other hosts	
        }}
    }}


    server {{
        listen 443 ssl;
        listen [::]:443 ssl;
        server_name {host_name};

        # SSL Config
        ssl_certificate /etc/nginx/ssl/live/{host_name}/fullchain.pem;
        ssl_certificate_key /etc/nginx/ssl/live/{host_name}/privkey.pem;

        ssl_session_cache shared:SSL:50m;
        ssl_session_timeout 5m;
        ssl_stapling on;
        ssl_stapling_verify on;

        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384";
        ssl_prefer_server_ciphers off;

        add_header Strict-Transport-Security "max-age=63072000" always;

        # Proxy
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Proto https;
        proxy_headers_hash_bucket_size 512;
        proxy_redirect off;

        # Websockets
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # init_redirect
        {redirects}
        # end_redirect
        
        #################################
        # LetsEncrypt                   #
        #################################
        location /.well-known/acme-challenge {{
            root /var/www/certbot;
            try_files $uri $uri/ =404;
        }}
    }}
"""

def printCurrentHosts(current):
  print("-------------------------------------------")
  print("Host name: " + current["host_name"])
  print("-------------------------------------------")
  print("Locations:")
  for location in current["locations"]:
    print(f"{location}: {current['locations'][location]}")
  print("-------------------------------------------")


def parseLocations(lines):
  locations = {}

  location = ""
  for line in lines:
    if "location" in line and location == "":
      location = line.split()[1]
    
    if "proxy_pass" in line and location != "":
      locations[location] = line.split()[1].split(":")[2].split(location)[0].split(";")[0]
      location = ""

  return locations


def readCurrentHosts():
  with open("conf/nginx.conf", "r") as file:
    lines = file.readlines()
    host_name = ""
    for line in lines:
      if "server_name" in line:
        host_name = line.split()[1].split(";")[0]
        break
    
    init_flag = False
    redirect_line = []
    for line in lines:
      if "init_redirect" in line:
        init_flag = True
      elif "end_redirect" in line:
        init_flag = False

      if init_flag:
        redirect_line.append(line)

    redirect_line = redirect_line[1:-1]

  return {
    "host_name": host_name,
    "locations": parseLocations(redirect_line)
  }


def generateHosts(current):
  basic = """
        location / {
          root /var/www;
          index index.html;
        }
  """

  redirects = ""

  if len(current["locations"]) == 0:
    redirects = basic
  else:
    for location in current["locations"]:
      redirects += f"""
        location {location} {{
          proxy_pass http://host.docker.internal:{current['locations'][location]};
        }}\n
      """
      
  file_template = generateTemplate(current["host_name"], redirects)
  with open("conf/nginx.conf", "w") as f:
    f.write(file_template)


current = readCurrentHosts()
while True:
  print("1. Set Host Name")
  print("2. Show Current Locations")
  print("3. Add new Location")
  print("4. Delete Location")
  print("5. Clean Locations")
  print("6. Exit")
  option = input("Enter an option: ")
  save_flag = False

  if option == "1":
    host_name = input("Enter Host Name: ")
    current["host_name"] = host_name
    print("The host name has been set")
    print(f"{current['host_name']}\n")
    save_flag = True

  if option == "2":
    printCurrentHosts(current)
  
  if option == "3":
    location = input("Enter Location: ")
    port = input("Enter Port Number: ")
    current["locations"][location] = port
    print("The location has been added")
    print(f"{location}: {current['locations'][location]}\n")
    save_flag = True

  if option == "4":
    location = input("Enter location: ")
    del current["locations"][location]
    print("The location has been deleted")
    print(f"{location}: {current['locations'][location]}\n")
    save_flag = True

  if option == "5":
    with open("conf/nginx.conf", "w") as f:
      f.write("")

    current["locations"] = {}
    print("All the Locations has been deleted\n")
    save_flag = True

  if option == "6":
    printCurrentHosts(current)
    generateHosts(current)
    break
  
  if save_flag:
    printCurrentHosts(current)
    generateHosts(current)