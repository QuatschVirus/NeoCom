using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading.Channels;
using WebSocketSharp;

namespace NeoCom.Client
{
    public class Client
    {
        protected CancellationTokenSource cts = new();

        public event Action<ConnectionState> ConnectionStateChanged;
        public event Action<ConnectionState, string> ConnectionStateChangedWithReason;
        public event Action<Error> ErrorRaised;
        public event Action<Message> MessageRecieved;
        public event Action<ClientQueryMessage.Request> CacheUpdated;
        public event Action<TextMessage> TextMessageRecieved;

        public ConnectionState State
        {
            get => state;
            protected set
            {
                if (state != value)
                {
                    ConnectionStateChanged.Invoke(value);
                }
                state = value;
            }
        }

        ConnectionState state = ConnectionState.None;

        protected WebSocket socket;
        protected readonly string configPath = "./config.json";

        public readonly ClientConfig config;
        public readonly User defaultIdentity;
        public User Identity => CurrentServer.identity ?? defaultIdentity;
        public Server CurrentServer { get; protected set; }
        public readonly Crypto crypto;

        public long Id { get; protected set; }

        public Client()
        {
            crypto = new();
            config = JsonSerializer.Deserialize<ClientConfig>(File.ReadAllText(configPath));
            defaultIdentity = new(crypto.GetKey(), config.name, config.displayName, config.nsfwEnabled && CheckNSFWAllowed());
        }

        protected void ChangeConnectionStateWithReason(ConnectionState state, string reason)
        {
            this.state = state;
            ConnectionStateChangedWithReason.Invoke(state, reason);
        }

        public ConnectionResult Connect(Server server)
        {   
            State = ConnectionState.Connecting;
            CurrentServer = server;
            socket = new(server.url);
            socket.OnOpen += OnConnectionOpen;
            socket.OnError += OnConnectionError;
            socket.OnClose += OnConnectionClose;
            socket.OnMessage += OnMessage;
            socket.SetCredentials(server.name, server.password, true);
            socket.Connect();

            Task.Delay(config.timeout, cts.Token).Wait();
            ResetCancel();

            if (State == ConnectionState.Connecting)
            {
                return ConnectionResult.Timeout;
            } else if (State == ConnectionState.Connected)
            {
                socket.Send(new ClientInitMessage(Identity));
                return ConnectionResult.Success;
            } else
            {
                return ConnectionResult.Other;
            }
        }

        private void OnMessage(object sender, MessageEventArgs e)
        {
            if (Message.TryFromSerial(e.RawData, out var msg))
            {
                switch (msg)
                {
                    case ServerInitMessage sIM:
                        {
                            if (sIM.Overriden)
                            {
                                switch (sIM.overrideKey)
                                {
                                    case ServerInitMessage.Override.ServerFull:
                                        {
                                            ChangeConnectionStateWithReason(ConnectionState.Disconnecting, $"The server is full. (max {BitConverter.ToInt64(sIM.overrideValue)} clients)");
                                            Disconnect();
                                            break;
                                        }
                                }
                                break;
                            }
                            Id = sIM.id;
                            CurrentServer.forcePassword = sIM.forcePassword;
                            CurrentServer.key = sIM.key;
                            RegisterChannels(sIM.initialChannels.ToList());
                            
                            if (State == ConnectionState.Connected)
                            {
                                State = ConnectionState.Ready;
                            }
                            break;
                        }
                    case ServerQueryMessage sQM:
                        {
                            switch (sQM.request)
                            {
                                case ServerQueryMessage.Request.User:
                                    {
                                        long id = BitConverter.ToInt64(sQM.data, 0);
                                        if (id == Id)
                                        {
                                            Send(new ClientQueryResponseMessage(sQM.request, id, Identity.Serialize()));
                                        }
                                        break;
                                    }
                            }
                            break;
                        }
                    case ServerQueryResponseMessage sQRM:
                        {
                            switch (sQRM.request)
                            {
                                case ClientQueryMessage.Request.UserInfo:
                                    {
                                        long id = BitConverter.ToInt64(sQRM.data, 0);
                                        User u = new(sQRM.data.Skip(8).ToArray());
                                        RegisterUser(id, u);
                                        break;
                                    }
                                case ClientQueryMessage.Request.Channel:
                                    {
                                        Channel c = new(sQRM.data, out var _);
                                        RegisterChannels(new List<Channel> { c });
                                        break;
                                    }
                                case ClientQueryMessage.Request.Group:
                                    {
                                        Group g = new(sQRM.data);
                                        RegisterGroups(new List<Group> { g });
                                        break;
                                    }
                                case ClientQueryMessage.Request.Groups:
                                    {
                                        throw new NotImplementedException();
                                    }
                            }
                        }
                        break;
                    case BroadcastTextMessage bTM:
                        {
                            ProcessTextMessage(bTM.message);
                            break;
                        }
                }
            } else
            {
                ErrorRaised.Invoke(new(Error.Code.UnkownMessage, $"Recieved message of unkown type: {BitConverter.ToString(e.RawData)}"));
            }
        }

        private void OnConnectionClose(object sender, CloseEventArgs e)
        {
            Disconnect();
        }

        private void OnConnectionError(object sender, WebSocketSharp.ErrorEventArgs e)
        {
            Console.WriteLine(e.Message);
            Console.WriteLine(e.Exception.GetType().Name);
            if (State == ConnectionState.Connecting)
            {
                cts.Cancel();
                State = ConnectionState.None;
            }
        }

        private void OnConnectionOpen(object sender, EventArgs e)
        {
            if (State == ConnectionState.Connecting)
            {
                cts.Cancel();
                State = ConnectionState.Connected;
            }
        }

        public void Disconnect()
        {
            State = ConnectionState.Disconnecting;
            socket.OnOpen -= OnConnectionOpen;
            socket.OnError -= OnConnectionError;
            socket.OnClose -= OnConnectionClose;
            socket.Close(CloseStatusCode.Normal);
        }

        public void RegisterUser(long id, User user)
        {
            _ = CurrentServer.users.TryAdd(id, user);
            CacheUpdated.Invoke(ClientQueryMessage.Request.UserInfo);
        }

        public void RegisterChannels(List<Channel> channels)
        {
            foreach (Channel c in channels)
            {
                CurrentServer.channels.Add(c.id, c);
                if (CurrentServer.groupChannels.TryAdd(c.group, new long[] { c.id }.ToList()))
                {
                    Send(ClientQueryMessage.QueryGroupInfo(Id, c.group));
                }
            }
            CacheUpdated.Invoke(ClientQueryMessage.Request.Channel);
        }

        public void RegisterGroups(List<Group> groups)
        {
            foreach (Group g in groups)
            {
                _ = CurrentServer.groups.TryAdd(g.id, g);
                _ = CurrentServer.groupChannels.TryAdd(g.id, new());
            }
            CacheUpdated.Invoke(ClientQueryMessage.Request.Group);
        }

        public void ProcessTextMessage(TextMessage msg)
        {
            if (CurrentServer.channels.ContainsKey(msg.channel))
            {
                CurrentServer.channels[msg.channel].messages.Add(msg);
                TextMessageRecieved.Invoke(msg);
            }
        }

        public virtual void Send(Message message)
        {
            if (State == ConnectionState.Ready)
            {
                socket.Send(message);
            }
        }

        public virtual void SendText(long channel, string message)
        {
            Send(new SendTextMessage(new(Id, channel, message, DateTime.Now)));
        }

        /// <summary>
        /// Override this method to determine wether the client is allowed ínto NSFW-channels
        /// </summary>
        /// <returns></returns>
        public virtual bool CheckNSFWAllowed()
        {
            return true;
        }

        protected void ResetCancel()
        {
            if (cts.IsCancellationRequested)
            {
                if (!cts.TryReset()) { cts.Dispose(); cts = new(); }
            }
        }
    }

    [Serializable]
    public class ClientConfig
    {
        public readonly List<Server> servers;
        public readonly string name;
        public readonly string displayName;
        public readonly bool nsfwEnabled;
        public readonly int timeout;
    }

    [Serializable]
    public class Server
    {
        public readonly string url;
        public readonly string name;
        public readonly User identity = null;
        public bool forcePassword;
        public byte[] key;
        public readonly string password;

        public readonly Dictionary<long, Channel> channels = new();
        public readonly Dictionary<int, Group> groups = new();
        public readonly Dictionary<int, List<long>> groupChannels = new();
        public readonly Dictionary<long, User> users = new();
    }

    public enum ConnectionState
    {
        None,
        Connecting,
        Connected,
        Ready,
        Disconnecting,
        Disconnected
    }

    public enum ConnectionResult
    {
        Success,
        AuthFail,
        Timeout,
        Other
    }

    public readonly struct Error
    {
        public enum Code
        {
            Unknown,
            UnkownMessage
        }

        public readonly Code code;
        public readonly string message;

        public Error(Code code, string message)
        {
            this.code = code;
            this.message = message;
        }

        public override string ToString()
        {
            return $"Error: {(int)code:X} {Enum.GetName<Code>(code)} '{message}'";
        }
    }
}