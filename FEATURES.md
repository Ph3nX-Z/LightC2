### Features to come

* HTTP/HTTPS listener (only one)
* Possibility to generate pe (service or basic pe or dll) with a base shellcode provided by the platform, that will create a remote shell to the tool (interactive)
* Possibility to execute-assembly (powershell)
* Possibility to migrate shell
* Malleable loader templates and loader store
* Shellcode store (only bin)
* Template store for basic things like adding a local administrator via a service
* Possibility to upload files and make it available from the c2 (upload or host)
* possibility to stage the shellcodes
* authentication on the c2 server (from cli)
* Team server and client differents (according to the arguments -client / -server)
* Possibility to use system proxy
* DB format
* Server multithreaded process
* Client cli
* Possibilité de mettre en place des modules (host un script powershell et iex en runtime)
* Messages de signalisation sur une page dediée pour avoir le status de l'agent
* Jitter et timeout (0 par defaut, interactif)
* Pipename hardcodé pour execution des commandes et recuperation stdout via pipe
* Mettre des champs remplacable au niveau des templates (pouvoir afficher un prompt en fonctiond d'un fichier conf donné par l'utilisateur pour configurer une template), avec characteres a remplacer, description et typage de l'entrée utilisateur
* Compilation via make, le fichier make doit etre fourni par l'utilisateur avec une commande de compilation pour chaques loaders, si aucune methode n'est entrée, il prendra une chaine par defaut



### Implemented features
