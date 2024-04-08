using System.Collections.Concurrent;
using System.ComponentModel;
using System.Reflection.Metadata.Ecma335;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace NeoCom
{
    public class Crypto
    {
        readonly RSACryptoServiceProvider rsa;

        public Crypto()
        {
            rsa = new();
        }

#pragma warning disable CA1822
        public byte[] Encrypt(byte[] data, byte[] key)
        {
            using RSACryptoServiceProvider rsa = new();
            rsa.ImportCspBlob(key);
            return rsa.Encrypt(data, false);
        }
#pragma warning restore CA1822

        public byte[] Decrypt(byte[] data)
        {
            return rsa.Decrypt(data, false);
        }

        public byte[] GetKey()
        {
            return rsa.ExportCspBlob(false);
        }
    }

    public class Message
    {
        readonly byte[] rawData;

        [Flags]
        public enum Leader
        {
            Server = 1 << 7,
            Id = 0b01111111,
            Init = 0,
            Query = 1,
            QueryResponse = 2,
            Text = 3,
            System = 4
        }

        public Message(byte[] raw)
        {
            rawData = raw;
        }

        public Message() { }

        public Message(Leader leader, bool server, byte[] data)
        {
            rawData = new byte[] { (byte)(server ? Leader.Server | leader : leader) }.Concat(data).ToArray();
        }

        public static bool TryFromSerial(byte[] data, out Message msg)
        {
            byte leader = data[0];
            bool server = (((byte)Leader.Server) & leader) != 0;

            switch (leader & (byte)Leader.Id)
            {
                case (int)Leader.Init:
                    {
                        msg = server ? new ServerInitMessage(data) : new ClientInitMessage(data);
                        break;
                    }
                case (int)Leader.Query:
                    {
                        msg = server ? new ServerQueryMessage(data) : new ClientQueryMessage(data);
                        break;
                    }
                case (int)Leader.QueryResponse:
                    {
                        msg = server ? new ServerQueryResponseMessage(data) : new ClientQueryResponseMessage(data);
                        break;
                    }
                case (int)Leader.Text:
                    {
                        msg = server ? new BroadcastTextMessage(data) : new SendTextMessage(data);
                        break;
                    }
                case (int)Leader.System:
                    {
                        msg = new SystemMessage(data);
                        break;
                    }
                default: msg = null; break;
            }

            if (msg == null)
            {
                return false;
            }
            else
            {
                return msg.Validate();
            }
        }

        public virtual byte[] Serialize() => rawData;
        public virtual bool Validate() => true;

        public static implicit operator byte[](Message messsage) => messsage.Serialize();
    }

    public class ClientInitMessage : Message
    {
        public readonly User user;

        public ClientInitMessage(byte[] data) : base(data)
        {
            user = new(data.Skip(1).ToArray());
        }

        public ClientInitMessage(User user)
        {
            this.user = user;
        }

        public override byte[] Serialize()
        {
            return new byte[] { (byte)Message.Leader.Init }.Concat(user.Serialize()).ToArray();
        }
    }

    public class ServerInitMessage : Message
    {
        public enum Override
        {
            None = 0,
            ServerFull = 0xFF
        }

        public readonly byte[] key;
        public readonly long id;
        public readonly Channel[] initialChannels;
        public readonly bool forcePassword;

        public readonly Override overrideKey = Override.None;
        public readonly byte[] overrideValue;

        public bool Overriden => overrideKey != Override.None;

        public ServerInitMessage(byte[] data) : base(data)
        {
            if (data[1] == 0)
            {
                overrideKey = (Override)data[2];
                overrideValue = data.Skip(3).ToArray();
            }

            int i = 0;
            key = new byte[data[i++]];
            byte flags = data[i++];

            forcePassword = (flags & 1) != 0;

            initialChannels = new Channel[BitConverter.ToInt32(data, i)];
            key = data.Skip(i += 4).Take(key.Length).ToArray();
            id = BitConverter.ToInt64(data, i += key.Length);
            i += 8;

            for (int n = 0; n < initialChannels.Length; n++)
            {
                initialChannels[n] = new(data.Skip(i).ToArray(), out int len);
                i += len;
            }
        }

        public ServerInitMessage(byte[] key, long id, bool forcePassword, Channel[] initialChannels)
        {
            this.key = key;
            this.id = id;
            this.forcePassword = forcePassword;
            this.initialChannels = initialChannels;
        }

        public ServerInitMessage(Override overrideKey, byte[] overrideValue)
        {
            this.overrideKey = overrideKey;
            this.overrideValue = overrideValue;
        }

        public override byte[] Serialize()
        {
            if (Overriden)
            {
                return new byte[] { (byte)(Leader.Server | Leader.Init), 0, (byte)overrideKey }.Concat(overrideValue).ToArray();
            }

            byte flags = 0;
            if (forcePassword) flags |= 1;

            byte[] data = new byte[] { (byte)(Leader.Server | Leader.Init), (byte)key.Length, flags }.Concat(BitConverter.GetBytes(initialChannels.Length)).Concat(key).Concat(BitConverter.GetBytes(id)).ToArray();
            foreach (Channel c in initialChannels)
            {
                data = data.Concat(c.Serialize()).ToArray();
            }
            return data;
        }

        public override bool Validate()
        {
            return initialChannels.All(c => c.present);
        }
    }

    public class ClientQueryMessage : Message
    {
        public enum Request
        {
            Fail,
            UserInfo,
            Channel,
            Group,
            Groups
        }

        public readonly Request request;
        public readonly byte[] data;
        public readonly long originId;

        public ClientQueryMessage(byte[] data) : base(data)
        {
            request = (Request)data[1];
            originId = BitConverter.ToInt64(data, 2);
            this.data = data.Skip(10).ToArray();
        }

        public ClientQueryMessage(Request request, long originId, byte[] data)
        {
            this.request = request;
            this.data = data;
            this.originId = originId;
        }

        public override byte[] Serialize()
        {
            return new byte[] { (byte)Message.Leader.Query, (byte)request }.Concat(BitConverter.GetBytes(originId)).Concat(data).ToArray();
        }

        public static ClientQueryMessage QueryUserInfo(long originId, long id)
        {
            return new(Request.UserInfo, originId, BitConverter.GetBytes(id));
        }

        public static ClientQueryMessage QueryChannelInfo(long originId, long id)
        {
            return new(Request.Channel, originId, BitConverter.GetBytes(id));
        }

        public static ClientQueryMessage QueryGroupInfo(long originId, int id)
        {
            return new(Request.Group, originId, BitConverter.GetBytes(id));
        }

        public static ClientQueryMessage QueryAllGroups(long originId)
        {
            return new(Request.Groups, originId, Array.Empty<byte>()); // Respond with id, name, displayname; not wit complete group info
        }
    }

    public class ServerQueryMessage : Message
    {
        public enum Request
        {
            Fail,
            User
        }

        public readonly Request request;
        public readonly byte[] data;

        public ServerQueryMessage(byte[] data) : base(data)
        {
            request = (Request)data[1];
            this.data = data.Skip(2).ToArray();
        }

        public ServerQueryMessage(Request request, byte[] data)
        {
            this.request = request;
            this.data = data;
        }

        public override byte[] Serialize()
        {
            return new byte[] { (byte)(Message.Leader.Server | Message.Leader.Query), (byte)request }.Concat(data).ToArray();
        }

        public static ServerQueryMessage QueryUserInfo(long id)
        {
            return new(Request.User, BitConverter.GetBytes(id));
        }
    }

    public class ClientQueryResponseMessage : Message
    {
        public readonly ServerQueryMessage.Request request;
        public readonly long originId;
        public readonly byte[] data;

        public ClientQueryResponseMessage(byte[] data) : base(data)
        {
            request = (ServerQueryMessage.Request)data[1];
            originId = BitConverter.ToInt64(data, 2);
            this.data = data.Skip(10).ToArray();
        }

        public ClientQueryResponseMessage(ServerQueryMessage.Request request, long originId, byte[] data)
        {
            this.request = request;
            this.originId = originId;
            this.data = data;
        }

        public override byte[] Serialize()
        {
            return new byte[] { (byte)Message.Leader.QueryResponse, (byte)request }.Concat(BitConverter.GetBytes(originId)).Concat(data).ToArray();
        }
    }

    public class ServerQueryResponseMessage : Message
    {
        public readonly ClientQueryMessage.Request request;
        public readonly long originId;
        public readonly byte[] data;

        public ServerQueryResponseMessage(byte[] data) : base(data)
        {
            request = (ClientQueryMessage.Request)data[1];
            originId = BitConverter.ToInt64(data, 2);
            this.data = data.Skip(10).ToArray();
        }

        public ServerQueryResponseMessage(ClientQueryMessage.Request request, long originId, byte[] data)
        {
            this.request = request;
            this.data = data;
            this.originId = originId;
        }

        public override byte[] Serialize()
        {
            return new byte[] { (byte)(Message.Leader.Server | Message.Leader.QueryResponse), (byte)request }.Concat(BitConverter.GetBytes(originId)).Concat(data).ToArray();
        }
    }

    public class SendTextMessage : Message
    {
        public readonly TextMessage message;

        public SendTextMessage(byte[] data) : base(data)
        {
            message = new TextMessage(data);
        }

        public SendTextMessage(TextMessage message)
        {
            this.message = message;
        }

        public override byte[] Serialize()
        {
            return message;
        }
    }

    public class BroadcastTextMessage : Message
    {
        public readonly TextMessage message;

        public BroadcastTextMessage(byte[] data) : base(data)
        {
            message = new TextMessage(data);
        }

        public BroadcastTextMessage(TextMessage message)
        {
            this.message = message;
        }

        public override byte[] Serialize()
        {
            return message;
        }
    }

    public class SystemMessage : Message
    {
        public readonly Reason reason;
        public readonly string explanation;

        public enum Reason
        {
            ServerStop,
            CriticalServerStop
        }

        public SystemMessage(byte[] data)
        {
            reason = (Reason)data[1];
            explanation = Encoding.UTF8.GetString(data.Skip(2).ToArray());
        }

        public SystemMessage(Reason reason, string explanation)
        {
            this.reason = reason;
            this.explanation = explanation;
        }

        public override byte[] Serialize()
        {
            return new byte[] { (byte)(Message.Leader.Server | Message.Leader.System), (byte)reason}.Concat(Encoding.UTF8.GetBytes(explanation)).ToArray();
        }
    }

    [Serializable]
    public class Channel
    {
        public readonly long id;
        public readonly int group;
        public readonly string name;
        public readonly string displayName;
        public readonly string description;

        public readonly List<TextMessage> messages = new();

        public bool present; // If true, will be sent in the ServerInitMessage to a client. If false, the client will need to query for more channels
        public bool nsfw;
        public bool passwordProtected;

        public byte[] password;

        public Channel(byte[] data, out int capturedLength)
        {
            int i = 0;
            byte flags = data[i++];
            id = BitConverter.ToInt64(data, i);
            group = BitConverter.ToInt32(data, i += 8);
            byte[] name = new byte[BitConverter.ToInt32(data, i += 4)];
            byte[] displayName = new byte[BitConverter.ToInt32(data, i += 4)];
            byte[] description = new byte[BitConverter.ToInt32(data, i += 4)];
            password = new byte[BitConverter.ToInt32(data, i += 4)];

            name = data.Skip(i).Take(name.Length).ToArray();
            displayName = data.Skip(i += name.Length).Take(displayName.Length).ToArray();
            description = data.Skip(i += displayName.Length).Take(description.Length).ToArray();
            password = data.Skip(i += description.Length).Take(password.Length).ToArray();
            i += password.Length;

            present = (flags & 1 << 0) != 0;
            nsfw = (flags & 1 << 1) != 0;
            passwordProtected = (flags & 1 << 2) != 0;

            this.name = Encoding.UTF8.GetString(name);
            this.displayName = Encoding.UTF8.GetString(displayName);
            this.description = Encoding.UTF8.GetString(description);

            capturedLength = i;
        }

        public Channel(long id, int group, string name, string displayName, string description, bool present, bool nsfw = false, bool passwordProtected = false, byte[] password = null)
        {
            this.id = id;
            this.group = group;
            this.name = name;
            this.displayName = displayName;
            this.description = description;
            this.present = present;
            this.nsfw = nsfw;
            this.passwordProtected = passwordProtected;
            this.password = password;
        }

        public Channel() : this(0L, 0, "main", "Main", "", true) { }

        public byte[] Serialize()
        {
            byte[] name = Encoding.UTF8.GetBytes(this.name);
            byte[] displayName = Encoding.UTF8.GetBytes(this.displayName);
            byte[] description = Encoding.UTF8.GetBytes(this.description);

            byte flags = 0;
            if (present) flags |= 1 << 0;
            if (nsfw) flags |= 1 << 1;
            if (passwordProtected) flags |= 1 << 2;

            return new byte[] { flags }.Concat(BitConverter.GetBytes(id)).Concat(BitConverter.GetBytes(group)).Concat(BitConverter.GetBytes(name.Length)).Concat(BitConverter.GetBytes(displayName.Length)).Concat(BitConverter.GetBytes(description.Length)).Concat(BitConverter.GetBytes(password.Length)).Concat(name).Concat(displayName).Concat(description).Concat(password).ToArray();
        }

        public override string ToString()
        {
            return $"{id:X16}: {displayName} ({name})";
        }
    }

    public class Group
    {
        public readonly int id;
        public readonly string name;
        public readonly string displayName;
        public readonly string description;

        public bool present; // If true, will be sent in the ServerInitMessage to a client. If false, the client will need to query for more groups
        public bool nsfw;
        public bool passwordProtected;

        public byte[] password;

        public Group(byte[] data)
        {
            int i = 0;
            byte flags = data[i++];
            id = BitConverter.ToInt32(data, i);
            byte[] name = new byte[BitConverter.ToInt32(data, i += 4)];
            byte[] displayName = new byte[BitConverter.ToInt32(data, i += 4)];
            byte[] description = new byte[BitConverter.ToInt32(data, i += 4)];
            password = new byte[BitConverter.ToInt32(data, i += 4)];

            name = data.Skip(i).Take(name.Length).ToArray();
            displayName = data.Skip(i += name.Length).Take(displayName.Length).ToArray();
            description = data.Skip(i += displayName.Length).Take(description.Length).ToArray();
            password = data.Skip(i += description.Length).Take(password.Length).ToArray();

            present = (flags & 1 << 0) != 0;
            nsfw = (flags & 1 << 1) != 0;
            passwordProtected = (flags & 1 << 2) != 0;

            this.name = Encoding.UTF8.GetString(name);
            this.displayName = Encoding.UTF8.GetString(displayName);
            this.description = Encoding.UTF8.GetString(description);
        }

        public Group(int id, string name, string displayName, string description, bool present, bool nsfw = false, bool passwordProtected = false, byte[] password = null)
        {
            this.id = id;
            this.name = name;
            this.displayName = displayName;
            this.description = description;
            this.present = present;
            this.nsfw = nsfw;
            this.passwordProtected = passwordProtected;
            this.password = password;
        }

        public Group() : this(0, "main", "Main", "", true) { }

        public byte[] Serialize()
        {
            byte[] name = Encoding.UTF8.GetBytes(this.name);
            byte[] displayName = Encoding.UTF8.GetBytes(this.displayName);
            byte[] description = Encoding.UTF8.GetBytes(this.description);

            byte flags = 0;
            if (present) flags |= 1 << 0;
            if (nsfw) flags |= 1 << 1;
            if (passwordProtected) flags |= 1 << 2;

            return new byte[] { flags }.Concat(BitConverter.GetBytes(id)).Concat(BitConverter.GetBytes(name.Length)).Concat(BitConverter.GetBytes(displayName.Length)).Concat(BitConverter.GetBytes(description.Length)).Concat(BitConverter.GetBytes(password.Length)).Concat(name).Concat(displayName).Concat(description).Concat(password).ToArray();
        }

        public override string ToString()
        {
            return $"{id:X8}: {displayName} ({name})";
        }
    }

    public class User
    {
        public readonly byte[] publicKey;
        public readonly string name;
        public readonly string displayName;
        public bool nsfwEnabled;

        public User(byte[] data)
        {
            int i = 0;
            byte flags = data[i++];
            publicKey = new byte[BitConverter.ToInt32(data, i)];
            byte[] name = new byte[BitConverter.ToInt32(data, i += 4)];
            byte[] displayName = new byte[BitConverter.ToInt32(data, i += 4)];

            publicKey = data.Skip(i).Take(publicKey.Length).ToArray();
            name = data.Skip(i += publicKey.Length).Take(name.Length).ToArray();
            displayName = data.Skip(i += name.Length).Take(displayName.Length).ToArray();

            nsfwEnabled = (flags & 1 << 0) != 0;
            this.name = Encoding.UTF8.GetString(name);
            this.displayName = Encoding.UTF8.GetString(displayName);
        }

        public User(byte[] publicKey, string name, string displayName, bool nsfwEnabled)
        {
            this.publicKey = publicKey;
            this.name = name;
            this.displayName = displayName;
            this.nsfwEnabled = nsfwEnabled;
        }

        public byte[] Serialize()
        {
            byte flags = 0;
            if (nsfwEnabled) flags |= 1 << 0;

            byte[] name = Encoding.UTF8.GetBytes(this.name);
            byte[] displayName = Encoding.UTF8.GetBytes(this.displayName);

            return new byte[] { flags }.Concat(BitConverter.GetBytes(publicKey.Length)).Concat(BitConverter.GetBytes(name.Length)).Concat(BitConverter.GetBytes(displayName.Length)).Concat(publicKey).Concat(name).Concat(displayName).ToArray();
        }
    }

    public readonly struct TextMessage
    {
        public readonly long sentBy;
        public readonly long channel;
        public readonly string message;
        public readonly DateTime sentAt;

        public TextMessage(byte[] data)
        {
            int i = 0;
            byte[] message = new byte[BitConverter.ToInt32(data, i++)];

            sentBy = BitConverter.ToInt64(data, i += 4);
            channel = BitConverter.ToInt64(data, i += 8);
            sentAt = DateTime.FromBinary(BitConverter.ToInt64(data, i += 8));
            message = data.Skip(i += 8).Take(message.Length).ToArray();

            this.message = Encoding.UTF8.GetString(message);
        }

        public TextMessage(long sentBy, long channel, string message, DateTime sentAt)
        {
            this.sentBy = sentBy;
            this.channel = channel;
            this.message = message;
            this.sentAt = sentAt;
        }

        public byte[] Serialize()
        {
            byte[] message = Encoding.UTF8.GetBytes(this.message);

            return new byte[] { (byte)Message.Leader.Text }.Concat(BitConverter.GetBytes(message.Length)).Concat(BitConverter.GetBytes(sentBy)).Concat(BitConverter.GetBytes(channel)).Concat(BitConverter.GetBytes(sentAt.ToBinary())).Concat(message).ToArray();
        }

        public static implicit operator byte[](TextMessage message)
        {
            return message.Serialize();
        }
    }

    public static class Helper
    {
        public static bool WaitForSingleEvent<TEvent>(this CancellationToken token, Action<TEvent> handler, Action<Action<TEvent>> subscribe, Action<Action<TEvent>> unsubscribe, int msTimeout, Action initializer = null)
        {
            var q = new BlockingCollection<TEvent>();
            void add(TEvent item) => q.TryAdd(item);
            subscribe(add);
            try
            {
                initializer?.Invoke();
                if (q.TryTake(out TEvent eventResult, msTimeout, token))
                {
                    handler(eventResult);
                    return true;
                }
                return false;
            }
            finally
            {
                unsubscribe(add);
                q.Dispose();
            }
        }
    }
}