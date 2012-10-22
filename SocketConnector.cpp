/*
 * Copyright (C) 2008-2011 TrinityCore <http://www.trinitycore.org/>
 * Copyright (C) 2005-2009 MaNGOS <http://getmangos.com/>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program. If not, see <http://www.gnu.org/licenses/>.
 */

/** \file
    \ingroup Trinityd
*/

#include "Common.h"
#include "Configuration/Config.h"
#include "Database/DatabaseEnv.h"
#include "AccountMgr.h"
#include "Log.h"
#include "SocketConnector.h"
#include "ChannelMgr.h"
#include "ObjectMgr.h"
#include "GuildMgr.h"
#include "Util.h"
#include "World.h"
#include "SHA1.h"
#include <string>

SocketConnector::Connections *SocketConnector::connections = new Connections();

SocketConnector::SocketConnector()
{
    
}

SocketConnector::~SocketConnector()
{
}

int SocketConnector::open(void *)
{
    ACE_INET_Addr remote_addr;

    if (peer().get_remote_addr(remote_addr) == -1)
    {
        sLog->outError(LOG_FILTER_WORLDSERVER, "SocketConnector::open: peer().get_remote_addr error is %s", ACE_OS::strerror(errno));
        return -1;
    }

    SocketConnector::connections->push_back(this);

    sLog->outDebug(LOG_FILTER_REMOTECOMMAND, "Incoming connection from %s", peer().get_remote_addr(remote_addr));

    return activate();
}

int SocketConnector::handle_close(ACE_HANDLE, ACE_Reactor_Mask)
{
    SocketConnector::connections->remove(this);
    sLog->outDebug(LOG_FILTER_REMOTECOMMAND, "SocketConnector: Closing connection");
    peer().close_reader();
    wait();
    destroy();
    return 0;
}

int SocketConnector::send(const std::string& line)
{
    return size_t(peer().send(line.c_str(), line.length())) == line.length() ? 0 : -1;
}

int SocketConnector::recv_line(ACE_Message_Block& buffer)
{
    char byte;
    for (;;)
    {
        ssize_t n = peer().recv(&byte, sizeof(byte));

        if (n < 0)
        {
            return -1;
        }

        if (n == 0)
        {
            // EOF, connection was closed
            errno = ECONNRESET;
            return -1;
        }

        ACE_ASSERT(n == sizeof(byte));

        if (byte == '\n' || byte == '\0')
            break;
        else if (byte == '\r') /* Ignore CR */
            continue;
        else if (buffer.copy(&byte, sizeof(byte)) == -1)
            return -1;
    }

    const char null_term = '\0';
    if (buffer.copy(&null_term, sizeof(null_term)) == -1)
        return -1;

    return 0;
}

int SocketConnector::recv_line(std::string& out_line)
{
    char buf[4096];

    ACE_Data_Block db(sizeof (buf),
            ACE_Message_Block::MB_DATA,
            buf,
            0,
            0,
            ACE_Message_Block::DONT_DELETE,
            0);

    ACE_Message_Block message_block(&db,
            ACE_Message_Block::DONT_DELETE,
            0);

    if (recv_line(message_block) == -1)
    {
        sLog->outError(LOG_FILTER_REMOTECOMMAND, "Recv error %s", ACE_OS::strerror(errno));
        return -1;
    }

    out_line = message_block.rd_ptr();

    return 0;
}

int SocketConnector::fill_user_data(const std::string& user)
{
    std::string safe_user = user;

    AccountMgr::normalizeString(safe_user);

    PreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_ACCOUNT_ID_BY_NAME);

    stmt->setString(0, safe_user);
    
    PreparedQueryResult result = LoginDatabase.Query(stmt);

    if (!result)
    {
        sLog->outDebug(LOG_FILTER_REMOTECOMMAND, "User %s does not exist in database", user.c_str());
        return -1;
    }

    accountGuid = result->Fetch()->GetUInt32();

    return 0;
}

int SocketConnector::check_password(const std::string& user, const std::string& pass)
{
    std::string safe_user = user;
    AccountMgr::normalizeString(safe_user);

    std::string safe_pass = pass;
    AccountMgr::normalizeString(safe_pass);

    std::string hash = AccountMgr::CalculateShaPassHash(safe_user, safe_pass);

    PreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_CHECK_PASSWORD_BY_NAME);

    stmt->setString(0, safe_user);
    stmt->setString(1, hash);

    PreparedQueryResult result = LoginDatabase.Query(stmt);

    if (!result)
    {
        sLog->outDebug(LOG_FILTER_REMOTECOMMAND, "Wrong password for user: %s", user.c_str());
        return -1;
    }

    stmt = LoginDatabase.GetPreparedStatement(LOGIN_GET_ACCOUNT_ID_BY_USERNAME);
    stmt->setString(0, safe_user);
    result = LoginDatabase.Query(stmt);

    uint32 accounId = (*result)[0].GetUInt32();

    QueryResult banresult = LoginDatabase.PQuery("SELECT 1 FROM account_banned WHERE id = '%d' AND active = '1'", accountGuid);

    if (banresult)
    {
        sLog->outDebug(LOG_FILTER_REMOTECOMMAND, "Account banned for user: %s", user.c_str());
        return -1;
    }

    return 0;
}

int SocketConnector::authenticate()
{
    std::string user;
    if (recv_line(user) == -1)
        return -1;

    //new --->
    if (user.compare("<policy-file-request/>") == 0)
    {
        const char* policy = "<?xml version=\"1.0\"?><cross-domain-policy><allow-access-from domain=\"*\" to-ports=\"*\" /></cross-domain-policy>" + (char)0;

        if (size_t(peer().send(policy, strlen(policy) + 1)) != strlen(policy) + 1)
            return -1;

        if (recv_line(user) == -1)
            return -1;
    }
    //<---- new

    std::string pass;
    if (recv_line(pass) == -1)
        return -1;

    sLog->outDebug(LOG_FILTER_REMOTECOMMAND, "Login attempt for user: %s", user.c_str());

    if (check_password(user, pass) == -1)
        return -1;

    if (fill_user_data(user) == -1)
        return -1;

    sLog->outDebug(LOG_FILTER_REMOTECOMMAND, "User login: %s", user.c_str());

    return 0;
}

int SocketConnector::select_character()
{
    //if (send(std::string("Char name: ")) == -1)
    //    return -1;

    std::string name;
    if (recv_line(name) == -1)
        return -1;
    
    CharacterDatabase.EscapeString(name);

    normalizePlayerName(name);

    QueryResult result = CharacterDatabase.PQuery("SELECT guid, name, race FROM characters WHERE name = '%s' AND account = '%d'", name.c_str(), accountGuid);
    if (!result)
    {
        sLog->outError(LOG_FILTER_REMOTECOMMAND, "Player %s does not exist in database", name.c_str());
        return -1;
    }
    Field *fields = result->Fetch();
    playerGuid = fields[0].GetUInt32();
    playerName = fields[1].GetString();

    uint8 r = fields[2].GetUInt8();
    playerFaction = r != 1 && r != 3 && r != 4 && r != 7 && r != 11;

    result = CharacterDatabase.PQuery("SELECT guildid FROM guild_member WHERE guid = '%d'", playerGuid);
    if (result)
    {
        fields = result->Fetch();
        guildGuid = fields[0].GetUInt32();
    }

    return 0;
}

int SocketConnector::get_characters()
{
    QueryResult result = CharacterDatabase.PQuery("SELECT name FROM characters WHERE account = '%d'", accountGuid);
    if (result)
    {
        Field *fields;
        std::string charNames = "";

        fields = result->Fetch();
        charNames += fields[0].GetString() + ",";

        while (result->NextRow())
        {
            fields = result->Fetch();
            charNames += fields[0].GetString() + ",";
        }

        send(charNames);
    }

    return 0;
}

int SocketConnector::sendMessage(const std::string& message)
{
    //std::string console;
    //utf8ToConsole(message, console);
    if (send(message) == -1)
        return -1;
    return 0;
}

int SocketConnector::sendToLFG(const std::string& message)
{
    uint32 team = playerFaction == 0 ? ALLIANCE : HORDE;

    if (ChannelMgr* cMgr = channelMgr(team))
    {
        ChannelMap::const_iterator i;
        
        for (i = cMgr->channels.begin(); i != cMgr->channels.end(); ++i)
        {
            if ((*i).second->IsLFG())
            {
                Channel *ch = (*i).second;

                uint32 messageLength = strlen(message.c_str()) + 1;
                uint32 lang = playerFaction == 0 ? LANG_COMMON : LANG_ORCISH;

                WorldPacket data(SMSG_MESSAGECHAT, 1+4+8+4+(ch->GetName()).size()+1+8+4+messageLength+1);
                data << (uint8)CHAT_MSG_CHANNEL;
                data << lang;
                data << playerGuid;
                data << uint32(0);
                data << ch->GetName();
                data << playerGuid;
                data << messageLength;
                data << message.c_str();
                data << uint8(0);

                ch->SendToAll(&data, false);

                std::list<SocketConnector*>::const_iterator iterator;
                for (iterator = SocketConnector::connections->begin(); iterator != SocketConnector::connections->end(); ++iterator)
                {
                    uint8 playerFaction = (*iterator)->playerFaction;
                    if ((*iterator)->playerGuid != playerGuid)
                    {
                        if (lang == LANG_UNIVERSAL || 
                            (lang == LANG_ORCISH && playerFaction == 1) || 
                            (lang == LANG_COMMON && playerFaction == 0) || 
                            sWorld->getBoolConfig(CONFIG_ALLOW_TWO_SIDE_INTERACTION_CHAT))
                        {
                            (*iterator)->sendMessage("m\\" + playerName + "\\" + message);
                        }
                    }
                }

                break;
            }
        }
    }

    return 0;
}

int SocketConnector::sendToPlayer(const std::string& message, std::string& receiverName)
{
    if (receiverName.empty())
        return false;

    wchar_t wstr_buf[MAX_INTERNAL_PLAYER_NAME+1];
    size_t wstr_len = MAX_INTERNAL_PLAYER_NAME;

    if (!Utf8toWStr(receiverName, &wstr_buf[0], wstr_len))
        return false;

    wstr_buf[0] = wcharToUpper(wstr_buf[0]);
    for (size_t i = 1; i < wstr_len; ++i)
        wstr_buf[i] = wcharToLower(wstr_buf[i]);

    if (!WStrToUtf8(wstr_buf, wstr_len, receiverName))
        return false;

    Player *player = sObjectAccessor->FindPlayerByName(receiverName.c_str());

    if (!player)
    {
        bool flag = false;
        std::list<SocketConnector*>::const_iterator iterator;
        for (iterator = SocketConnector::connections->begin(); iterator != SocketConnector::connections->end(); ++iterator)
        {
            if ((*iterator)->playerName.compare(receiverName.c_str()) == 0)
            {
                int receiverFaction = (*iterator)->playerFaction;
                if (receiverFaction == playerFaction || sWorld->getBoolConfig(CONFIG_ALLOW_TWO_SIDE_INTERACTION_CHAT))
                {
                    (*iterator)->sendMessage("w\\" + playerName + "\\" + message);
                    flag = true;
                    break;
                }
            }
        }

        if (!flag)
            return -1;
    }
    else
    {
        uint8 r = player->getRace();
        uint8 receiverFaction = r != 1 && r != 3 && r != 4 && r != 7 && r != 11;

        if (sWorld->getBoolConfig(CONFIG_ALLOW_TWO_SIDE_INTERACTION_CHAT) || playerFaction == receiverFaction)
        {
            WorldPacket data(SMSG_MESSAGECHAT, 200);
            data << uint8(CHAT_MSG_WHISPER);
            data << uint32(LANG_UNIVERSAL);
            data << uint64(playerGuid);
            data << uint32(LANG_UNIVERSAL);
            data << uint64(playerGuid);
            data << uint32(message.length() + 1);
            data << message;
            data << uint8(0);
            player->GetSession()->SendPacket(&data);
        }
        return -1;
    }
    return 0;
}

int SocketConnector::sendToGuild(const std::string& message)
{
    if (Guild *guild = sGuildMgr->GetGuildById(guildGuid))
    {
        WorldPacket data(SMSG_MESSAGECHAT, 200);
        data << (uint8)CHAT_MSG_GUILD;
        data << LANG_UNIVERSAL;
        data << playerGuid;
        data << uint32(0);
        data << playerGuid;
        data << (strlen(message.c_str()) + 1);
        data << message.c_str();
        data << uint8(0);

        guild->BroadcastPacket(&data);

        std::list<SocketConnector*>::const_iterator iterator;
        for (iterator = SocketConnector::connections->begin(); iterator != SocketConnector::connections->end(); ++iterator)
        {
            if ((*iterator)->guildGuid == guildGuid && ((*iterator)->playerGuid != playerGuid))
            {
                (*iterator)->sendMessage("g\\" + playerName + "\\" + message);
            }
        }
    }
    else
    {
        return -1;
    }

    return 0;
}

int SocketConnector::svc(void)
{    
    if (authenticate() == -1)
    {
        (void) send("Authentication failed");
        return -1;
    }

    get_characters();

    if (select_character() == -1)
    {
        (void) send("Character not found");
        return -1;
    }

    // send motd
    if (send(std::string(sWorld->GetMotd()) + "") == -1)
        return -1;
    
    sLog->outDebug(LOG_FILTER_REMOTECOMMAND, "Player connected: %s", playerName.c_str());
    for(;;)
    {
        // show prompt
        //const char* tc_prompt = "TC> ";
        //if (size_t(peer().send(tc_prompt, strlen(tc_prompt))) != strlen(tc_prompt))
        //    return -1;

        std::string line;

        if (recv_line(line) == -1)
            return -1;

        QueryResult result = LoginDatabase.PQuery("SELECT mutetime FROM account WHERE id = '%d'", accountGuid);
        if (!result) return -1;

        Field *fields = result->Fetch();
        time_t muteTime = fields[0].GetInt64();

        if (muteTime > time(NULL)) return -1;

        if (line.substr(0, 2) == "m\\")
        {
            sendToLFG(line.substr(2));
        }
        else if (line.substr(0, 2) == "g\\")
        {
            sendToGuild(line.substr(2));
        }
        else if (line.substr(0, 2) == "w\\")
        {
            std::string receiver = line.substr(2, line.find("\\", 3, 1) - 2);
            std::string message = line.substr(line.find("\\", receiver.length(), 1) + 1);
            sLog->outDebug(LOG_FILTER_REMOTECOMMAND, receiver.c_str());
            sLog->outDebug(LOG_FILTER_REMOTECOMMAND, message.c_str());
            sendToPlayer(message, receiver);
        }
        else if (line == "getchars")
        {
            get_characters();
        }
        else if (line == "quit" || line == "exit" || line == "logout")
            return -1;
    }

    return 0;
}
