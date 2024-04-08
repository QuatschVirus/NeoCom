using WebSocketSharp;
using WebSocketSharp.Server;
using System.Net;
using System.Text.Json;

namespace NeoCom.Server
{
    class Behaviour: WebSocketBehavior
    {
        Server server;

        public Behaviour() { }

        public void Init(Server server)
        {
            this.server = server;
        }

        protected override void OnClose(CloseEventArgs e)
        {
            base.OnClose(e);
        }

        protected override void OnError(WebSocketSharp.ErrorEventArgs e)
        {
            base.OnError(e);
        }

        protected override void OnMessage(MessageEventArgs e)
        {
            base.OnMessage(e);
            if (Message.TryFromSerial(e.RawData, out var message))
            {
                switch (message)
                {
                    case ClientInitMessage cIM:
                        {
                            long id = GetNewUserId();
                            if (id == 0)
                            {
                                Send(new ServerInitMessage(ServerInitMessage.Override.ServerFull, BitConverter.GetBytes(server.config.maxUsers))); // Server is full
                            } else
                            {
                                _ = server.users.TryAdd(id, cIM.user);
                                Send(new ServerInitMessage(server.crypto.GetKey(), id, server.config.forcePassword, server.initialChannels.ToArray()).Serialize());
                            }
                            break;
                        }
                    case ClientQueryMessage cQM:
                        {
                            long originId = cQM.originId;
                            byte[] data = cQM.data;

                            ServerQueryResponseMessage msg = null;
                            switch (cQM.request)
                            {
                                case ClientQueryMessage.Request.UserInfo:
                                    {
                                        long id = BitConverter.ToInt64(data, 0);
                                        if (server.users.TryGetValue(id, out var user))
                                        {
                                            msg = new(cQM.request, originId, BitConverter.GetBytes(id).Concat(user.Serialize()).ToArray());
                                        } else
                                        {
                                            msg = new(ClientQueryMessage.Request.Fail, originId, new byte[] { 0x10 });
                                        }
                                        break;
                                    }
                                case ClientQueryMessage.Request.Channel:
                                    {
                                        long id = BitConverter.ToInt64(data, 0);
                                        if (server.channels.TryGetValue(id, out var channel))
                                        {
                                            msg = new(cQM.request, originId, channel.Serialize()); 
                                        } else
                                        {
                                            msg = new(ClientQueryMessage.Request.Fail, originId, new byte[] { 0x10 });
                                        }
                                        break;
                                    }
                                case ClientQueryMessage.Request.Group:
                                    {
                                        int id = BitConverter.ToInt32(data, 0);
                                        if (server.groups.TryGetValue(id, out var group))
                                        {
                                            msg = new(cQM.request, originId, group.Serialize());
                                        }
                                        else
                                        {
                                            msg = new(ClientQueryMessage.Request.Fail, originId, new byte[] { 0x10 });
                                        }
                                        break;
                                    }
                                case ClientQueryMessage.Request.Groups:
                                    {
                                        IEnumerable<byte> groups = BitConverter.GetBytes(server.groups.Count);

                                        foreach (Group g in server.groups.Values)
                                        {
                                            groups = groups.Concat(g.Serialize());
                                        }

                                        msg = new(cQM.request, originId, groups.ToArray());
                                        break;
                                    }
                            }

                            if (msg != null)
                            {
                                Send(msg);
                            } else
                            {
                                Send(new ServerQueryResponseMessage(ClientQueryMessage.Request.Fail, originId, new byte[] { 0xFF }));
                            }
                            break;
                        }
                    case ClientQueryResponseMessage cQRM:
                        {
                            long originId = cQRM.originId;
                            byte[] data = cQRM.data;

                            switch (cQRM.request)
                            {
                                case ServerQueryMessage.Request.User:
                                    {
                                        server.users[originId] = new(data);
                                        break;
                                    }
                            }

                            break;
                        }
                    case SendTextMessage sTM:
                        {
                            Sessions.Broadcast(new BroadcastTextMessage(sTM.message));
                            break;
                        }

                }
            }
        }

        protected override void OnOpen()
        {
            base.OnOpen();
        }

        long GetNewUserId()
        {
            if (server.users.Count >= server.config.maxUsers)
            {
                return 0;
            }

            long id;
            do
            {
                id = server.random.NextInt64();
            } while (server.users.ContainsKey(id) && id == 0);
            return id;
        }
    }

    public class Server
    {
        readonly WebSocketServer server;
        readonly WebSocketSessionManager sessions;
        readonly string configPath = "./config.json";
        public readonly ServerConfig config;
        public readonly Logging log = new("./server.log");
        public readonly Crypto crypto = new();

        public readonly Dictionary<long, User> users = new();
        public readonly Random random = new();

        public readonly Dictionary<long, Channel> channels = new();
        public readonly Dictionary<int, Group> groups = new();
        public readonly Dictionary<int, List<long>> groupChannels = new();

        public readonly List<Channel> initialChannels = new();

        public Server()
        {
            log.BeforeExitOnCritical += () =>
            {
                if (server != null)
                {
                    log.Warn("CriticalServerStop", "The server is stopping due to a critical error");
                    BroadcastAll(new(SystemMessage.Reason.CriticalServerStop, "There was a critical error, and this server is stopping"));
                    server.Stop();
                }
            };

            // TODO: ASCII ART
            config = JsonSerializer.Deserialize<ServerConfig>(File.ReadAllText(configPath));

            if (config == null)
            {
                log.CriticalError("ConfigFailure", "The configuration has failed to load correctly");
                return;
            }

            foreach (Group g in config.groups)
            {
                groups.Add(g.id, g);
                groupChannels.Add(g.id, new());
            }

            foreach (Channel c in config.channels)
            {
                channels.Add(c.id, c);
                groupChannels[c.group].Add(c.id);
                if (c.present) initialChannels.Add(c);
            }

            server = new(IPAddress.Parse(config.url), config.port);
            server.AddWebSocketService<Behaviour>("", b => b.Init(this));
            sessions = server.WebSocketServices.Hosts.First().Sessions;

            server.AuthenticationSchemes = WebSocketSharp.Net.AuthenticationSchemes.Basic;
            server.Realm = config.name;
            server.UserCredentialsFinder = id => new(config.name, config.password);

            log.Info("Starting socket...");
            server.Start();
        }

        public void BroadcastAll(SystemMessage msg)
        {
            sessions.Broadcast(msg.Serialize());
        }
    }

    [Serializable]
    public class ServerConfig
    {
        public readonly string name = "server";
        public readonly string password = "password";
        public readonly bool forcePassword = false;
        public readonly string url = "127.0.0.1";
        public readonly int port = 5000;
        public readonly long maxUsers = long.MaxValue;
        public readonly List<Channel> channels = new Channel[1].ToList();
        public readonly List<Group> groups = new Group[1].ToList();
    }
}