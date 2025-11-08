<p align="center">
  <img src="https://github.com/user-attachments/assets/eff841b4-b4d6-4b7f-8226-1e6c318ddfaa" alt="Keydra_1024" width="40%" />
  <img src="https://github.com/user-attachments/assets/189fb8a6-e981-40d3-a9da-2acc889e6394" alt="Aegis_1024" width="40%" />
</p>

# Keydra & Aegis
Keydra is gonna be the raw sockets tool. Aegis is the command server which uses Keydra on the backend to connect to clients.

## Aegis
Right now, Keydra (on the server side) is going to be comprised of:
- A central API server for end users (God willing, containerized)
- A central Redis server (containerized)
- A central server for handling the raw sockets

Per end user, the Keydra CLI (right now this is also on the server..) will:
- Review logs (Command execution history, responses, client connection list, etc)
- Push commands to redis so the raw sockets server can read and send to clients
- Save scripts to run against hosts, and review things which have previously run (this is the first bullet but why im doing it)
- Pattern match from existing hosts (in real time?) thru regex (hopefully) to capture who commands are run against
- Alias commands to be used multiple times (Including keydra calls- ex: regex for hosts in current list matching a pattern, compare against old hosts, and run on any new ones?)
- Save variables to be referenced in aliased commands? Could be cool
- Event driven logic (Host connects, run some kind of persistence script? Possibly build in P2P c2 functionality with raw socket tool to alert who is available thru the new host?)

## Keydra
Raw Socket was written by https://github.com/oneNutW0nder/CatTails 
I am adding some features and trying to fix some of the problems, but really, all the hard work was done by him

See his talk on it here:
https://www.youtube.com/watch?v=BwfRsTK4PS0

Or his article on it here:
https://ritcsec.wordpress.com/2020/04/28/internals-of-cattails-a-c2-bot-framework-2/