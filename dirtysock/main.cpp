#include "main.h"
#include <stdio.h>

UINT64 p[938];

// --- Load Plugins ---
void loadPlugins (FILE *Log, char *folder)
{
	DWORD typeMask = 0x6973612e; // '.asi'
	WIN32_FIND_DATA fd;
	char targetfilter[FILENAME_MAX];
	char currfile[FILENAME_MAX];
	strcpy (targetfilter, ".\\");
	strcat (targetfilter, folder);
	strcat (targetfilter, "\\*.asi");

	HANDLE asiFile = FindFirstFile (targetfilter, &fd);
	if (asiFile == INVALID_HANDLE_VALUE)
        return;
	do
	{
		if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
		{
			int pos = 0;
			while (fd.cFileName[pos])
				pos++;
			DWORD type = *(DWORD *)(fd.cFileName+pos-4);
			type |= 0x20202020; // convert letter to lowercase, "\0" to space
			if (type == typeMask)
			{
				strcpy (currfile, ".\\");
				strcat (currfile, folder);
				strcat (currfile, "\\");
				strcat (currfile, fd.cFileName);
				if (LoadLibrary (currfile))
					fprintf (Log, "Plugin loaded: %s\n", currfile);
				else
					fprintf (Log, "Plugin error: %s\n", currfile);
			}
		}
	} while (FindNextFile (asiFile, &fd));
	FindClose (asiFile);
}

DWORD WINAPI Start(LPVOID lpParam)
{
    FILE *Log = fopen("dirtysockLOG.txt", "w" );
    fprintf(Log, "Dirtysock DLL Proxy by Erik JS\n");
    HINSTANCE hL = LoadLibrary("dirtysock.bak");
    if(!hL)
    {
        fprintf(Log, "Error loading dirtysock.bak!\n");
        fclose(Log);
        return 0;
    }
    p[0] = (UINT64)GetProcAddress(hL, "Base64Decode");
    p[1] = (UINT64)GetProcAddress(hL, "Base64Decode2");
    p[2] = (UINT64)GetProcAddress(hL, "Base64Decode3");
    p[3] = (UINT64)GetProcAddress(hL, "Base64Encode");
    p[4] = (UINT64)GetProcAddress(hL, "Base64Encode2");
    p[5] = (UINT64)GetProcAddress(hL, "Binary7Decode");
    p[6] = (UINT64)GetProcAddress(hL, "Binary7Encode");
    p[7] = (UINT64)GetProcAddress(hL, "BuddyApiAdd");
    p[8] = (UINT64)GetProcAddress(hL, "BuddyApiBroadcast");
    p[9] = (UINT64)GetProcAddress(hL, "BuddyApiBuddyInvite");
    p[10] = (UINT64)GetProcAddress(hL, "BuddyApiConfig");
    p[11] = (UINT64)GetProcAddress(hL, "BuddyApiConnect");
    p[12] = (UINT64)GetProcAddress(hL, "BuddyApiCreate2");
    p[13] = (UINT64)GetProcAddress(hL, "BuddyApiDebug");
    p[14] = (UINT64)GetProcAddress(hL, "BuddyApiDel");
    p[15] = (UINT64)GetProcAddress(hL, "BuddyApiDestroy");
    p[16] = (UINT64)GetProcAddress(hL, "BuddyApiDisconnect");
    p[17] = (UINT64)GetProcAddress(hL, "BuddyApiDomain");
    p[18] = (UINT64)GetProcAddress(hL, "BuddyApiFind");
    p[19] = (UINT64)GetProcAddress(hL, "BuddyApiFindUsers");
    p[20] = (UINT64)GetProcAddress(hL, "BuddyApiFlush");
    p[21] = (UINT64)GetProcAddress(hL, "BuddyApiGameInvite");
    p[22] = (UINT64)GetProcAddress(hL, "BuddyApiGetForwarding");
    p[23] = (UINT64)GetProcAddress(hL, "BuddyApiGetMyTitleName");
    p[24] = (UINT64)GetProcAddress(hL, "BuddyApiGetTitleName");
    p[25] = (UINT64)GetProcAddress(hL, "BuddyApiGetUserSessionID");
    p[26] = (UINT64)GetProcAddress(hL, "BuddyApiJoinGame");
    p[27] = (UINT64)GetProcAddress(hL, "BuddyApiPresDiff");
    p[28] = (UINT64)GetProcAddress(hL, "BuddyApiPresExFlags");
    p[29] = (UINT64)GetProcAddress(hL, "BuddyApiPresExtra");
    p[30] = (UINT64)GetProcAddress(hL, "BuddyApiPresInit");
    p[31] = (UINT64)GetProcAddress(hL, "BuddyApiPresJoinable");
    p[32] = (UINT64)GetProcAddress(hL, "BuddyApiPresNoText");
    p[33] = (UINT64)GetProcAddress(hL, "BuddyApiPresSame");
    p[34] = (UINT64)GetProcAddress(hL, "BuddyApiPresSend");
    p[35] = (UINT64)GetProcAddress(hL, "BuddyApiRecv");
    p[36] = (UINT64)GetProcAddress(hL, "BuddyApiRefreshTitle");
    p[37] = (UINT64)GetProcAddress(hL, "BuddyApiRegisterBuddyChangeCallback");
    p[38] = (UINT64)GetProcAddress(hL, "BuddyApiRegisterBuddyDelCallback");
    p[39] = (UINT64)GetProcAddress(hL, "BuddyApiResource");
    p[40] = (UINT64)GetProcAddress(hL, "BuddyApiRespondBuddy");
    p[41] = (UINT64)GetProcAddress(hL, "BuddyApiRespondGame");
    p[42] = (UINT64)GetProcAddress(hL, "BuddyApiResumeXDK");
    p[43] = (UINT64)GetProcAddress(hL, "BuddyApiRoster");
    p[44] = (UINT64)GetProcAddress(hL, "BuddyApiRosterList");
    p[45] = (UINT64)GetProcAddress(hL, "BuddyApiSend");
    p[46] = (UINT64)GetProcAddress(hL, "BuddyApiSetForwarding");
    p[47] = (UINT64)GetProcAddress(hL, "BuddyApiSetGameInviteSessionID");
    p[48] = (UINT64)GetProcAddress(hL, "BuddyApiStatus");
    p[49] = (UINT64)GetProcAddress(hL, "BuddyApiSuspendXDK");
    p[50] = (UINT64)GetProcAddress(hL, "BuddyApiUpdate");
    p[51] = (UINT64)GetProcAddress(hL, "BuddyApiUserFound");
    p[52] = (UINT64)GetProcAddress(hL, "CommSRPCallback");
    p[53] = (UINT64)GetProcAddress(hL, "CommSRPConnect");
    p[54] = (UINT64)GetProcAddress(hL, "CommSRPConstruct");
    p[55] = (UINT64)GetProcAddress(hL, "CommSRPDestroy");
    p[56] = (UINT64)GetProcAddress(hL, "CommSRPListen");
    p[57] = (UINT64)GetProcAddress(hL, "CommSRPPeek");
    p[58] = (UINT64)GetProcAddress(hL, "CommSRPRecv");
    p[59] = (UINT64)GetProcAddress(hL, "CommSRPResolve");
    p[60] = (UINT64)GetProcAddress(hL, "CommSRPSend");
    p[61] = (UINT64)GetProcAddress(hL, "CommSRPStatus");
    p[62] = (UINT64)GetProcAddress(hL, "CommSRPTick");
    p[63] = (UINT64)GetProcAddress(hL, "CommSRPUnconnect");
    p[64] = (UINT64)GetProcAddress(hL, "CommSRPUnlisten");
    p[65] = (UINT64)GetProcAddress(hL, "CommSRPUnresolve");
    p[66] = (UINT64)GetProcAddress(hL, "CommTAPICallback");
    p[67] = (UINT64)GetProcAddress(hL, "CommTAPIConnect");
    p[68] = (UINT64)GetProcAddress(hL, "CommTAPIConstruct");
    p[69] = (UINT64)GetProcAddress(hL, "CommTAPIDestroy");
    p[70] = (UINT64)GetProcAddress(hL, "CommTAPIListen");
    p[71] = (UINT64)GetProcAddress(hL, "CommTAPIPeek");
    p[72] = (UINT64)GetProcAddress(hL, "CommTAPIRecv");
    p[73] = (UINT64)GetProcAddress(hL, "CommTAPIResolve");
    p[74] = (UINT64)GetProcAddress(hL, "CommTAPISend");
    p[75] = (UINT64)GetProcAddress(hL, "CommTAPIStatus");
    p[76] = (UINT64)GetProcAddress(hL, "CommTAPITick");
    p[77] = (UINT64)GetProcAddress(hL, "CommTAPIUnconnect");
    p[78] = (UINT64)GetProcAddress(hL, "CommTAPIUnlisten");
    p[79] = (UINT64)GetProcAddress(hL, "CommTAPIUnresolve");
    p[80] = (UINT64)GetProcAddress(hL, "CommTCPCallback");
    p[81] = (UINT64)GetProcAddress(hL, "CommTCPConnect");
    p[82] = (UINT64)GetProcAddress(hL, "CommTCPConstruct");
    p[83] = (UINT64)GetProcAddress(hL, "CommTCPDestroy");
    p[84] = (UINT64)GetProcAddress(hL, "CommTCPListen");
    p[85] = (UINT64)GetProcAddress(hL, "CommTCPPeek");
    p[86] = (UINT64)GetProcAddress(hL, "CommTCPRecv");
    p[87] = (UINT64)GetProcAddress(hL, "CommTCPResolve");
    p[88] = (UINT64)GetProcAddress(hL, "CommTCPSend");
    p[89] = (UINT64)GetProcAddress(hL, "CommTCPStatus");
    p[90] = (UINT64)GetProcAddress(hL, "CommTCPTick");
    p[91] = (UINT64)GetProcAddress(hL, "CommTCPUnconnect");
    p[92] = (UINT64)GetProcAddress(hL, "CommTCPUnlisten");
    p[93] = (UINT64)GetProcAddress(hL, "CommTCPUnresolve");
    p[94] = (UINT64)GetProcAddress(hL, "CommUDPCallback");
    p[95] = (UINT64)GetProcAddress(hL, "CommUDPConnect");
    p[96] = (UINT64)GetProcAddress(hL, "CommUDPConstruct");
    p[97] = (UINT64)GetProcAddress(hL, "CommUDPControl");
    p[98] = (UINT64)GetProcAddress(hL, "CommUDPDestroy");
    p[99] = (UINT64)GetProcAddress(hL, "CommUDPListen");
    p[100] = (UINT64)GetProcAddress(hL, "CommUDPPeek");
    p[101] = (UINT64)GetProcAddress(hL, "CommUDPRecv");
    p[102] = (UINT64)GetProcAddress(hL, "CommUDPResolve");
    p[103] = (UINT64)GetProcAddress(hL, "CommUDPSend");
    p[104] = (UINT64)GetProcAddress(hL, "CommUDPStatus");
    p[105] = (UINT64)GetProcAddress(hL, "CommUDPTick");
    p[106] = (UINT64)GetProcAddress(hL, "CommUDPUnconnect");
    p[107] = (UINT64)GetProcAddress(hL, "CommUDPUnlisten");
    p[108] = (UINT64)GetProcAddress(hL, "CommUDPUnresolve");
    p[109] = (UINT64)GetProcAddress(hL, "ConnApiAddCallback");
    p[110] = (UINT64)GetProcAddress(hL, "ConnApiAddClient");
    p[111] = (UINT64)GetProcAddress(hL, "ConnApiAddUser");
    p[112] = (UINT64)GetProcAddress(hL, "ConnApiConnect");
    p[113] = (UINT64)GetProcAddress(hL, "ConnApiControl");
    p[114] = (UINT64)GetProcAddress(hL, "ConnApiCreate2");
    p[115] = (UINT64)GetProcAddress(hL, "ConnApiDestroy");
    p[116] = (UINT64)GetProcAddress(hL, "ConnApiDisconnect");
    p[117] = (UINT64)GetProcAddress(hL, "ConnApiFindClient");
    p[118] = (UINT64)GetProcAddress(hL, "ConnApiFindClientById");
    p[119] = (UINT64)GetProcAddress(hL, "ConnApiGetClientList");
    p[120] = (UINT64)GetProcAddress(hL, "ConnApiMigratePlatformHost");
    p[121] = (UINT64)GetProcAddress(hL, "ConnApiMigrateTopologyHost");
    p[122] = (UINT64)GetProcAddress(hL, "ConnApiOnline");
    p[123] = (UINT64)GetProcAddress(hL, "ConnApiRematch");
    p[124] = (UINT64)GetProcAddress(hL, "ConnApiRemoveCallback");
    p[125] = (UINT64)GetProcAddress(hL, "ConnApiRemoveClient");
    p[126] = (UINT64)GetProcAddress(hL, "ConnApiRemoveUser");
    p[127] = (UINT64)GetProcAddress(hL, "ConnApiSetPresence");
    p[128] = (UINT64)GetProcAddress(hL, "ConnApiStart");
    p[129] = (UINT64)GetProcAddress(hL, "ConnApiStatus");
    p[130] = (UINT64)GetProcAddress(hL, "ConnApiStatus2");
    p[131] = (UINT64)GetProcAddress(hL, "ConnApiStop");
    p[132] = (UINT64)GetProcAddress(hL, "ConnApiUpdate");
    p[133] = (UINT64)GetProcAddress(hL, "CryptAesDecrypt");
    p[134] = (UINT64)GetProcAddress(hL, "CryptAesEncrypt");
    p[135] = (UINT64)GetProcAddress(hL, "CryptAesInit");
    p[136] = (UINT64)GetProcAddress(hL, "CryptArc4Advance");
    p[137] = (UINT64)GetProcAddress(hL, "CryptArc4Apply");
    p[138] = (UINT64)GetProcAddress(hL, "CryptArc4Init");
    p[139] = (UINT64)GetProcAddress(hL, "CryptArc4StringDecrypt");
    p[140] = (UINT64)GetProcAddress(hL, "CryptArc4StringEncrypt");
    p[141] = (UINT64)GetProcAddress(hL, "CryptArc4StringEncryptStaticCode");
    p[142] = (UINT64)GetProcAddress(hL, "CryptHashGet");
    p[143] = (UINT64)GetProcAddress(hL, "CryptHashGetSize");
    p[144] = (UINT64)GetProcAddress(hL, "CryptHmacCalc");
    p[145] = (UINT64)GetProcAddress(hL, "CryptHmacCalcMulti");
    p[146] = (UINT64)GetProcAddress(hL, "CryptMD2Final");
    p[147] = (UINT64)GetProcAddress(hL, "CryptMD2Init");
    p[148] = (UINT64)GetProcAddress(hL, "CryptMD2Init2");
    p[149] = (UINT64)GetProcAddress(hL, "CryptMD2Update");
    p[150] = (UINT64)GetProcAddress(hL, "CryptMD5Final");
    p[151] = (UINT64)GetProcAddress(hL, "CryptMD5Init");
    p[152] = (UINT64)GetProcAddress(hL, "CryptMD5Init2");
    p[153] = (UINT64)GetProcAddress(hL, "CryptMD5Update");
    p[154] = (UINT64)GetProcAddress(hL, "CryptRSAEncrypt");
    p[155] = (UINT64)GetProcAddress(hL, "CryptRSAInit");
    p[156] = (UINT64)GetProcAddress(hL, "CryptRSAInitMaster");
    p[157] = (UINT64)GetProcAddress(hL, "CryptRSAInitPrivate");
    p[158] = (UINT64)GetProcAddress(hL, "CryptRSAInitSignature");
    p[159] = (UINT64)GetProcAddress(hL, "CryptRandGet");
    p[160] = (UINT64)GetProcAddress(hL, "CryptRandInit");
    p[161] = (UINT64)GetProcAddress(hL, "CryptRandShutdown");
    p[162] = (UINT64)GetProcAddress(hL, "CryptSSC2Apply");
    p[163] = (UINT64)GetProcAddress(hL, "CryptSSC2Init");
    p[164] = (UINT64)GetProcAddress(hL, "CryptSSC2StringDecrypt");
    p[165] = (UINT64)GetProcAddress(hL, "CryptSSC2StringEncrypt");
    p[166] = (UINT64)GetProcAddress(hL, "CryptSha1Final");
    p[167] = (UINT64)GetProcAddress(hL, "CryptSha1Init");
    p[168] = (UINT64)GetProcAddress(hL, "CryptSha1Init2");
    p[169] = (UINT64)GetProcAddress(hL, "CryptSha1Update");
    p[170] = (UINT64)GetProcAddress(hL, "CryptSha2Final");
    p[171] = (UINT64)GetProcAddress(hL, "CryptSha2Init");
    p[172] = (UINT64)GetProcAddress(hL, "CryptSha2Update");
    p[173] = (UINT64)GetProcAddress(hL, "CryptStp1DecryptData");
    p[174] = (UINT64)GetProcAddress(hL, "CryptStp1DecryptHash");
    p[175] = (UINT64)GetProcAddress(hL, "CryptStp1DecryptSize");
    p[176] = (UINT64)GetProcAddress(hL, "CryptStp1Enabled");
    p[177] = (UINT64)GetProcAddress(hL, "CryptStp1EncryptData");
    p[178] = (UINT64)GetProcAddress(hL, "CryptStp1EncryptHash");
    p[179] = (UINT64)GetProcAddress(hL, "CryptStp1EncryptSize");
    p[180] = (UINT64)GetProcAddress(hL, "CryptStp1MakeWallet");
    p[181] = (UINT64)GetProcAddress(hL, "CryptStp1OpenWallet");
    p[182] = (UINT64)GetProcAddress(hL, "CryptStp1SetShared");
    p[183] = (UINT64)GetProcAddress(hL, "CryptStp1UseSecret");
    p[184] = (UINT64)GetProcAddress(hL, "CryptStp1UseTicket");
    p[185] = (UINT64)GetProcAddress(hL, "DirtyAddrFromHostAddr");
    p[186] = (UINT64)GetProcAddress(hL, "DirtyAddrGetLocalAddr");
    p[187] = (UINT64)GetProcAddress(hL, "DirtyAddrToHostAddr");
    p[188] = (UINT64)GetProcAddress(hL, "DirtyCertCAPreloadCerts");
    p[189] = (UINT64)GetProcAddress(hL, "DirtyCertCARequestCert");
    p[190] = (UINT64)GetProcAddress(hL, "DirtyCertCARequestDone");
    p[191] = (UINT64)GetProcAddress(hL, "DirtyCertCARequestFree");
    p[192] = (UINT64)GetProcAddress(hL, "DirtyCertControl");
    p[193] = (UINT64)GetProcAddress(hL, "DirtyCertCreate");
    p[194] = (UINT64)GetProcAddress(hL, "DirtyCertDestroy");
    p[195] = (UINT64)GetProcAddress(hL, "DirtyCertStatus");
    p[196] = (UINT64)GetProcAddress(hL, "DirtyErrGetHResult");
    p[197] = (UINT64)GetProcAddress(hL, "DirtyGifDecodeImage");
    p[198] = (UINT64)GetProcAddress(hL, "DirtyGifDecodeImage32");
    p[199] = (UINT64)GetProcAddress(hL, "DirtyGifDecodePalette");
    p[200] = (UINT64)GetProcAddress(hL, "DirtyGifIdentify");
    p[201] = (UINT64)GetProcAddress(hL, "DirtyGifParse");
    p[202] = (UINT64)GetProcAddress(hL, "DirtyGraphCreate");
    p[203] = (UINT64)GetProcAddress(hL, "DirtyGraphDecodeHeader");
    p[204] = (UINT64)GetProcAddress(hL, "DirtyGraphDecodeImage");
    p[205] = (UINT64)GetProcAddress(hL, "DirtyGraphDestroy");
    p[206] = (UINT64)GetProcAddress(hL, "DirtyJpgCreate");
    p[207] = (UINT64)GetProcAddress(hL, "DirtyJpgDecodeHeader");
    p[208] = (UINT64)GetProcAddress(hL, "DirtyJpgDecodeImage");
    p[209] = (UINT64)GetProcAddress(hL, "DirtyJpgDestroy");
    p[210] = (UINT64)GetProcAddress(hL, "DirtyJpgIdentify");
    p[211] = (UINT64)GetProcAddress(hL, "DirtyJpgReset");
    p[212] = (UINT64)GetProcAddress(hL, "DirtyMemAlloc");
    p[213] = (UINT64)GetProcAddress(hL, "DirtyMemFree");
    p[214] = (UINT64)GetProcAddress(hL, "DirtyMemFuncSet");
    p[215] = (UINT64)GetProcAddress(hL, "DirtyMemGroupEnter");
    p[216] = (UINT64)GetProcAddress(hL, "DirtyMemGroupLeave");
    p[217] = (UINT64)GetProcAddress(hL, "DirtyMemGroupQuery");
    p[218] = (UINT64)GetProcAddress(hL, "DirtyNameCreateCanonical");
    p[219] = (UINT64)GetProcAddress(hL, "DirtyPngCreate");
    p[220] = (UINT64)GetProcAddress(hL, "DirtyPngDecodeImage");
    p[221] = (UINT64)GetProcAddress(hL, "DirtyPngDestroy");
    p[222] = (UINT64)GetProcAddress(hL, "DirtyPngIdentify");
    p[223] = (UINT64)GetProcAddress(hL, "DirtyPngParse");
    p[224] = (UINT64)GetProcAddress(hL, "DirtyUsernameCompare");
    p[225] = (UINT64)GetProcAddress(hL, "DirtyUsernameHash");
    p[226] = (UINT64)GetProcAddress(hL, "DirtyUsernameSubstr");
    p[227] = (UINT64)GetProcAddress(hL, "DispListAdd");
    p[228] = (UINT64)GetProcAddress(hL, "DispListChange");
    p[229] = (UINT64)GetProcAddress(hL, "DispListClear");
    p[230] = (UINT64)GetProcAddress(hL, "DispListCount");
    p[231] = (UINT64)GetProcAddress(hL, "DispListCreate");
    p[232] = (UINT64)GetProcAddress(hL, "DispListDataGet");
    p[233] = (UINT64)GetProcAddress(hL, "DispListDataSet");
    p[234] = (UINT64)GetProcAddress(hL, "DispListDel");
    p[235] = (UINT64)GetProcAddress(hL, "DispListDelByIndex");
    p[236] = (UINT64)GetProcAddress(hL, "DispListDestroy");
    p[237] = (UINT64)GetProcAddress(hL, "DispListDirty");
    p[238] = (UINT64)GetProcAddress(hL, "DispListFilt");
    p[239] = (UINT64)GetProcAddress(hL, "DispListGet");
    p[240] = (UINT64)GetProcAddress(hL, "DispListIndex");
    p[241] = (UINT64)GetProcAddress(hL, "DispListOrder");
    p[242] = (UINT64)GetProcAddress(hL, "DispListSet");
    p[243] = (UINT64)GetProcAddress(hL, "DispListShown");
    p[244] = (UINT64)GetProcAddress(hL, "DispListSort");
    p[245] = (UINT64)GetProcAddress(hL, "FriendApiAddCallback");
    p[246] = (UINT64)GetProcAddress(hL, "FriendApiBlockUser");
    p[247] = (UINT64)GetProcAddress(hL, "FriendApiControl");
    p[248] = (UINT64)GetProcAddress(hL, "FriendApiCreate");
    p[249] = (UINT64)GetProcAddress(hL, "FriendApiDestroy");
    p[250] = (UINT64)GetProcAddress(hL, "FriendApiGetBlockList");
    p[251] = (UINT64)GetProcAddress(hL, "FriendApiGetBlockListVersion");
    p[252] = (UINT64)GetProcAddress(hL, "FriendApiGetFriendsList");
    p[253] = (UINT64)GetProcAddress(hL, "FriendApiGetFriendsListVersion");
    p[254] = (UINT64)GetProcAddress(hL, "FriendApiIsUserBlocked");
    p[255] = (UINT64)GetProcAddress(hL, "FriendApiRemoveCallback");
    p[256] = (UINT64)GetProcAddress(hL, "FriendApiStatus");
    p[257] = (UINT64)GetProcAddress(hL, "FriendApiUnblockUser");
    p[258] = (UINT64)GetProcAddress(hL, "FriendApiUpdate");
    p[259] = (UINT64)GetProcAddress(hL, "HLBApiCancelOp");
    p[260] = (UINT64)GetProcAddress(hL, "HLBApiConnect");
    p[261] = (UINT64)GetProcAddress(hL, "HLBApiCreate");
    p[262] = (UINT64)GetProcAddress(hL, "HLBApiCreate2");
    p[263] = (UINT64)GetProcAddress(hL, "HLBApiDestroy");
    p[264] = (UINT64)GetProcAddress(hL, "HLBApiDisconnect");
    p[265] = (UINT64)GetProcAddress(hL, "HLBApiFindUsers");
    p[266] = (UINT64)GetProcAddress(hL, "HLBApiGetConnectState");
    p[267] = (UINT64)GetProcAddress(hL, "HLBApiGetEmailForwarding");
    p[268] = (UINT64)GetProcAddress(hL, "HLBApiGetLastOpStatus");
    p[269] = (UINT64)GetProcAddress(hL, "HLBApiGetMyTitleName");
    p[270] = (UINT64)GetProcAddress(hL, "HLBApiGetTitleName");
    p[271] = (UINT64)GetProcAddress(hL, "HLBApiGetUserIndex");
    p[272] = (UINT64)GetProcAddress(hL, "HLBApiInitialize");
    p[273] = (UINT64)GetProcAddress(hL, "HLBApiOverrideConstants");
    p[274] = (UINT64)GetProcAddress(hL, "HLBApiOverrideMaxMessagesPerBuddy");
    p[275] = (UINT64)GetProcAddress(hL, "HLBApiOverrideXblIsSameProductCheck");
    p[276] = (UINT64)GetProcAddress(hL, "HLBApiPresenceDiff");
    p[277] = (UINT64)GetProcAddress(hL, "HLBApiPresenceExtra");
    p[278] = (UINT64)GetProcAddress(hL, "HLBApiPresenceJoinable");
    p[279] = (UINT64)GetProcAddress(hL, "HLBApiPresenceOffline");
    p[280] = (UINT64)GetProcAddress(hL, "HLBApiPresenceSame");
    p[281] = (UINT64)GetProcAddress(hL, "HLBApiPresenceSend");
    p[282] = (UINT64)GetProcAddress(hL, "HLBApiPresenceSendSetPresence");
    p[283] = (UINT64)GetProcAddress(hL, "HLBApiPresenceVOIPSend");
    p[284] = (UINT64)GetProcAddress(hL, "HLBApiRegisterBuddyChangeCallback");
    p[285] = (UINT64)GetProcAddress(hL, "HLBApiRegisterBuddyPresenceCallback");
    p[286] = (UINT64)GetProcAddress(hL, "HLBApiRegisterConnectCallback");
    p[287] = (UINT64)GetProcAddress(hL, "HLBApiRegisterGameInviteCallback");
    p[288] = (UINT64)GetProcAddress(hL, "HLBApiRegisterNewMsgCallback");
    p[289] = (UINT64)GetProcAddress(hL, "HLBApiResume");
    p[290] = (UINT64)GetProcAddress(hL, "HLBApiSetDebugFunction");
    p[291] = (UINT64)GetProcAddress(hL, "HLBApiSetEmailForwarding");
    p[292] = (UINT64)GetProcAddress(hL, "HLBApiSetUserIndex");
    p[293] = (UINT64)GetProcAddress(hL, "HLBApiSetUtf8TransTbl");
    p[294] = (UINT64)GetProcAddress(hL, "HLBApiSuspend");
    p[295] = (UINT64)GetProcAddress(hL, "HLBApiUpdate");
    p[296] = (UINT64)GetProcAddress(hL, "HLBApiUserFound");
    p[297] = (UINT64)GetProcAddress(hL, "HLBBudCanVoiceChat");
    p[298] = (UINT64)GetProcAddress(hL, "HLBBudGetGameInviteFlags");
    p[299] = (UINT64)GetProcAddress(hL, "HLBBudGetName");
    p[300] = (UINT64)GetProcAddress(hL, "HLBBudGetPresence");
    p[301] = (UINT64)GetProcAddress(hL, "HLBBudGetPresenceExtra");
    p[302] = (UINT64)GetProcAddress(hL, "HLBBudGetState");
    p[303] = (UINT64)GetProcAddress(hL, "HLBBudGetTitle");
    p[304] = (UINT64)GetProcAddress(hL, "HLBBudGetVOIPState");
    p[305] = (UINT64)GetProcAddress(hL, "HLBBudIsAvailableForChat");
    p[306] = (UINT64)GetProcAddress(hL, "HLBBudIsBlocked");
    p[307] = (UINT64)GetProcAddress(hL, "HLBBudIsIWannaBeHisBuddy");
    p[308] = (UINT64)GetProcAddress(hL, "HLBBudIsInGroup");
    p[309] = (UINT64)GetProcAddress(hL, "HLBBudIsJoinable");
    p[310] = (UINT64)GetProcAddress(hL, "HLBBudIsNoReplyBud");
    p[311] = (UINT64)GetProcAddress(hL, "HLBBudIsPassive");
    p[312] = (UINT64)GetProcAddress(hL, "HLBBudIsRealBuddy");
    p[313] = (UINT64)GetProcAddress(hL, "HLBBudIsSameProduct");
    p[314] = (UINT64)GetProcAddress(hL, "HLBBudIsTemporary");
    p[315] = (UINT64)GetProcAddress(hL, "HLBBudIsWannaBeMyBuddy");
    p[316] = (UINT64)GetProcAddress(hL, "HLBBudJoinGame");
    p[317] = (UINT64)GetProcAddress(hL, "HLBBudTempBuddyIs");
    p[318] = (UINT64)GetProcAddress(hL, "HLBListAddToGroup");
    p[319] = (UINT64)GetProcAddress(hL, "HLBListAnswerGameInvite");
    p[320] = (UINT64)GetProcAddress(hL, "HLBListAnswerInvite");
    p[321] = (UINT64)GetProcAddress(hL, "HLBListBlockBuddy");
    p[322] = (UINT64)GetProcAddress(hL, "HLBListBuddyWithMsg");
    p[323] = (UINT64)GetProcAddress(hL, "HLBListCancelAllInvites");
    p[324] = (UINT64)GetProcAddress(hL, "HLBListCancelGameInvite");
    p[325] = (UINT64)GetProcAddress(hL, "HLBListChanged");
    p[326] = (UINT64)GetProcAddress(hL, "HLBListClearGroup");
    p[327] = (UINT64)GetProcAddress(hL, "HLBListDeleteTempBuddy");
    p[328] = (UINT64)GetProcAddress(hL, "HLBListDisableSorting");
    p[329] = (UINT64)GetProcAddress(hL, "HLBListFlagTempBuddy");
    p[330] = (UINT64)GetProcAddress(hL, "HLBListGameInviteBuddy");
    p[331] = (UINT64)GetProcAddress(hL, "HLBListGetBuddyByIndex");
    p[332] = (UINT64)GetProcAddress(hL, "HLBListGetBuddyByName");
    p[333] = (UINT64)GetProcAddress(hL, "HLBListGetBuddyCount");
    p[334] = (UINT64)GetProcAddress(hL, "HLBListGetBuddyCountByFlags");
    p[335] = (UINT64)GetProcAddress(hL, "HLBListGetGameSessionID");
    p[336] = (UINT64)GetProcAddress(hL, "HLBListGetIndexByName");
    p[337] = (UINT64)GetProcAddress(hL, "HLBListInviteBuddy");
    p[338] = (UINT64)GetProcAddress(hL, "HLBListRemoveFromGroup");
    p[339] = (UINT64)GetProcAddress(hL, "HLBListSendChatMsg");
    p[340] = (UINT64)GetProcAddress(hL, "HLBListSendMsgToGroup");
    p[341] = (UINT64)GetProcAddress(hL, "HLBListSetGameInviteSessionID");
    p[342] = (UINT64)GetProcAddress(hL, "HLBListSetSortFunction");
    p[343] = (UINT64)GetProcAddress(hL, "HLBListUnBlockBuddy");
    p[344] = (UINT64)GetProcAddress(hL, "HLBListUnFlagTempBuddy");
    p[345] = (UINT64)GetProcAddress(hL, "HLBListUnMakeBuddy");
    p[346] = (UINT64)GetProcAddress(hL, "HLBMsgListDelete");
    p[347] = (UINT64)GetProcAddress(hL, "HLBMsgListDeleteAll");
    p[348] = (UINT64)GetProcAddress(hL, "HLBMsgListGetFirstUnreadMsg");
    p[349] = (UINT64)GetProcAddress(hL, "HLBMsgListGetMsgByIndex");
    p[350] = (UINT64)GetProcAddress(hL, "HLBMsgListGetMsgText");
    p[351] = (UINT64)GetProcAddress(hL, "HLBMsgListGetTotalCount");
    p[352] = (UINT64)GetProcAddress(hL, "HLBMsgListGetUnreadCount");
    p[353] = (UINT64)GetProcAddress(hL, "HLBMsgListMsgInject");
    p[354] = (UINT64)GetProcAddress(hL, "HashNumAdd");
    p[355] = (UINT64)GetProcAddress(hL, "HashNumDel");
    p[356] = (UINT64)GetProcAddress(hL, "HashNumFind");
    p[357] = (UINT64)GetProcAddress(hL, "HashNumReplace");
    p[358] = (UINT64)GetProcAddress(hL, "HashStrAdd");
    p[359] = (UINT64)GetProcAddress(hL, "HashStrDel");
    p[360] = (UINT64)GetProcAddress(hL, "HashStrFind");
    p[361] = (UINT64)GetProcAddress(hL, "HashStrReplace");
    p[362] = (UINT64)GetProcAddress(hL, "HasherClear");
    p[363] = (UINT64)GetProcAddress(hL, "HasherCount");
    p[364] = (UINT64)GetProcAddress(hL, "HasherCreate");
    p[365] = (UINT64)GetProcAddress(hL, "HasherDestroy");
    p[366] = (UINT64)GetProcAddress(hL, "HasherEnum");
    p[367] = (UINT64)GetProcAddress(hL, "HasherEnumInit");
    p[368] = (UINT64)GetProcAddress(hL, "HasherExpand");
    p[369] = (UINT64)GetProcAddress(hL, "HasherFlush");
    p[370] = (UINT64)GetProcAddress(hL, "HasherSetStrCompareFunc");
    p[371] = (UINT64)GetProcAddress(hL, "HttpManagerAlloc");
    p[372] = (UINT64)GetProcAddress(hL, "HttpManagerCallback");
    p[373] = (UINT64)GetProcAddress(hL, "HttpManagerControl");
    p[374] = (UINT64)GetProcAddress(hL, "HttpManagerCreate");
    p[375] = (UINT64)GetProcAddress(hL, "HttpManagerDestroy");
    p[376] = (UINT64)GetProcAddress(hL, "HttpManagerFree");
    p[377] = (UINT64)GetProcAddress(hL, "HttpManagerGet");
    p[378] = (UINT64)GetProcAddress(hL, "HttpManagerPost");
    p[379] = (UINT64)GetProcAddress(hL, "HttpManagerRecv");
    p[380] = (UINT64)GetProcAddress(hL, "HttpManagerRecvAll");
    p[381] = (UINT64)GetProcAddress(hL, "HttpManagerRequestCb");
    p[382] = (UINT64)GetProcAddress(hL, "HttpManagerSend");
    p[383] = (UINT64)GetProcAddress(hL, "HttpManagerSetBaseUrl");
    p[384] = (UINT64)GetProcAddress(hL, "HttpManagerStatus");
    p[385] = (UINT64)GetProcAddress(hL, "HttpManagerUpdate");
    p[386] = (UINT64)GetProcAddress(hL, "JsonAddDate");
    p[387] = (UINT64)GetProcAddress(hL, "JsonAddInt");
    p[388] = (UINT64)GetProcAddress(hL, "JsonAddNum");
    p[389] = (UINT64)GetProcAddress(hL, "JsonAddStr");
    p[390] = (UINT64)GetProcAddress(hL, "JsonArrayEnd");
    p[391] = (UINT64)GetProcAddress(hL, "JsonArrayStart");
    p[392] = (UINT64)GetProcAddress(hL, "JsonBufSizeIncrease");
    p[393] = (UINT64)GetProcAddress(hL, "JsonFind");
    p[394] = (UINT64)GetProcAddress(hL, "JsonFind2");
    p[395] = (UINT64)GetProcAddress(hL, "JsonFinish");
    p[396] = (UINT64)GetProcAddress(hL, "JsonFormatPrintf");
    p[397] = (UINT64)GetProcAddress(hL, "JsonFormatVPrintf");
    p[398] = (UINT64)GetProcAddress(hL, "JsonGetBoolean");
    p[399] = (UINT64)GetProcAddress(hL, "JsonGetDate");
    p[400] = (UINT64)GetProcAddress(hL, "JsonGetEnum");
    p[401] = (UINT64)GetProcAddress(hL, "JsonGetInteger");
    p[402] = (UINT64)GetProcAddress(hL, "JsonGetListItemEnd");
    p[403] = (UINT64)GetProcAddress(hL, "JsonGetNumber");
    p[404] = (UINT64)GetProcAddress(hL, "JsonGetString");
    p[405] = (UINT64)GetProcAddress(hL, "JsonInit");
    p[406] = (UINT64)GetProcAddress(hL, "JsonObjectEnd");
    p[407] = (UINT64)GetProcAddress(hL, "JsonObjectStart");
    p[408] = (UINT64)GetProcAddress(hL, "JsonParse");
    p[409] = (UINT64)GetProcAddress(hL, "JsonSeekValue");
    p[410] = (UINT64)GetProcAddress(hL, "LobbyLanControl");
    p[411] = (UINT64)GetProcAddress(hL, "LobbyLanCreate2");
    p[412] = (UINT64)GetProcAddress(hL, "LobbyLanCreateGame");
    p[413] = (UINT64)GetProcAddress(hL, "LobbyLanDestroy");
    p[414] = (UINT64)GetProcAddress(hL, "LobbyLanGetGameInfo");
    p[415] = (UINT64)GetProcAddress(hL, "LobbyLanGetGameList");
    p[416] = (UINT64)GetProcAddress(hL, "LobbyLanGetPlyrList");
    p[417] = (UINT64)GetProcAddress(hL, "LobbyLanJoinGame");
    p[418] = (UINT64)GetProcAddress(hL, "LobbyLanJoinGameByIndex");
    p[419] = (UINT64)GetProcAddress(hL, "LobbyLanLeaveGame");
    p[420] = (UINT64)GetProcAddress(hL, "LobbyLanRecvfrom");
    p[421] = (UINT64)GetProcAddress(hL, "LobbyLanReset");
    p[422] = (UINT64)GetProcAddress(hL, "LobbyLanSendto");
    p[423] = (UINT64)GetProcAddress(hL, "LobbyLanSetCallback");
    p[424] = (UINT64)GetProcAddress(hL, "LobbyLanSetNote");
    p[425] = (UINT64)GetProcAddress(hL, "LobbyLanSetPlyrNote");
    p[426] = (UINT64)GetProcAddress(hL, "LobbyLanStartGame");
    p[427] = (UINT64)GetProcAddress(hL, "LobbyLanStatus");
    p[428] = (UINT64)GetProcAddress(hL, "LobbyMSort");
    p[429] = (UINT64)GetProcAddress(hL, "MurmurHash3");
    p[430] = (UINT64)GetProcAddress(hL, "MurmurHash3Final");
    p[431] = (UINT64)GetProcAddress(hL, "MurmurHash3Init");
    p[432] = (UINT64)GetProcAddress(hL, "MurmurHash3Init2");
    p[433] = (UINT64)GetProcAddress(hL, "MurmurHash3Update");
    p[434] = (UINT64)GetProcAddress(hL, "NetConnConnect");
    p[435] = (UINT64)GetProcAddress(hL, "NetConnControl");
    p[436] = (UINT64)GetProcAddress(hL, "NetConnCopyParam");
    p[437] = (UINT64)GetProcAddress(hL, "NetConnDirtyCertCreate");
    p[438] = (UINT64)GetProcAddress(hL, "NetConnDisconnect");
    p[439] = (UINT64)GetProcAddress(hL, "NetConnElapsed");
    p[440] = (UINT64)GetProcAddress(hL, "NetConnGetEnvStr");
    p[441] = (UINT64)GetProcAddress(hL, "NetConnIdle");
    p[442] = (UINT64)GetProcAddress(hL, "NetConnIdleAdd");
    p[443] = (UINT64)GetProcAddress(hL, "NetConnIdleDel");
    p[444] = (UINT64)GetProcAddress(hL, "NetConnIdleShutdown");
    p[445] = (UINT64)GetProcAddress(hL, "NetConnMAC");
    p[446] = (UINT64)GetProcAddress(hL, "NetConnMachineId");
    p[447] = (UINT64)GetProcAddress(hL, "NetConnQuery");
    p[448] = (UINT64)GetProcAddress(hL, "NetConnSetMachineId");
    p[449] = (UINT64)GetProcAddress(hL, "NetConnShutdown");
    p[450] = (UINT64)GetProcAddress(hL, "NetConnSleep");
    p[451] = (UINT64)GetProcAddress(hL, "NetConnStartup");
    p[452] = (UINT64)GetProcAddress(hL, "NetConnStatus");
    p[453] = (UINT64)GetProcAddress(hL, "NetConnTiming");
    p[454] = (UINT64)GetProcAddress(hL, "NetCritEnter");
    p[455] = (UINT64)GetProcAddress(hL, "NetCritInit");
    p[456] = (UINT64)GetProcAddress(hL, "NetCritKill");
    p[457] = (UINT64)GetProcAddress(hL, "NetCritLeave");
    p[458] = (UINT64)GetProcAddress(hL, "NetCritTry");
    p[459] = (UINT64)GetProcAddress(hL, "NetGameDistControl");
    p[460] = (UINT64)GetProcAddress(hL, "NetGameDistCreate");
    p[461] = (UINT64)GetProcAddress(hL, "NetGameDistDestroy");
    p[462] = (UINT64)GetProcAddress(hL, "NetGameDistGetError");
    p[463] = (UINT64)GetProcAddress(hL, "NetGameDistGetErrorText");
    p[464] = (UINT64)GetProcAddress(hL, "NetGameDistInputCheck");
    p[465] = (UINT64)GetProcAddress(hL, "NetGameDistInputClear");
    p[466] = (UINT64)GetProcAddress(hL, "NetGameDistInputLocal");
    p[467] = (UINT64)GetProcAddress(hL, "NetGameDistInputLocalMulti");
    p[468] = (UINT64)GetProcAddress(hL, "NetGameDistInputPeek");
    p[469] = (UINT64)GetProcAddress(hL, "NetGameDistInputQuery");
    p[470] = (UINT64)GetProcAddress(hL, "NetGameDistInputQueryMulti");
    p[471] = (UINT64)GetProcAddress(hL, "NetGameDistInputRate");
    p[472] = (UINT64)GetProcAddress(hL, "NetGameDistMetaSetup");
    p[473] = (UINT64)GetProcAddress(hL, "NetGameDistMultiSetup");
    p[474] = (UINT64)GetProcAddress(hL, "NetGameDistResetError");
    p[475] = (UINT64)GetProcAddress(hL, "NetGameDistSendStats");
    p[476] = (UINT64)GetProcAddress(hL, "NetGameDistServAddClient");
    p[477] = (UINT64)GetProcAddress(hL, "NetGameDistServControl");
    p[478] = (UINT64)GetProcAddress(hL, "NetGameDistServCreate");
    p[479] = (UINT64)GetProcAddress(hL, "NetGameDistServDelClient");
    p[480] = (UINT64)GetProcAddress(hL, "NetGameDistServDestroy");
    p[481] = (UINT64)GetProcAddress(hL, "NetGameDistServDiscClient");
    p[482] = (UINT64)GetProcAddress(hL, "NetGameDistServExplainError");
    p[483] = (UINT64)GetProcAddress(hL, "NetGameDistServHighWaterChanged");
    p[484] = (UINT64)GetProcAddress(hL, "NetGameDistServStartGame");
    p[485] = (UINT64)GetProcAddress(hL, "NetGameDistServStatus");
    p[486] = (UINT64)GetProcAddress(hL, "NetGameDistServStopGame");
    p[487] = (UINT64)GetProcAddress(hL, "NetGameDistServUpdate");
    p[488] = (UINT64)GetProcAddress(hL, "NetGameDistServUpdateClient");
    p[489] = (UINT64)GetProcAddress(hL, "NetGameDistSetProc");
    p[490] = (UINT64)GetProcAddress(hL, "NetGameDistSetServer");
    p[491] = (UINT64)GetProcAddress(hL, "NetGameDistStatus");
    p[492] = (UINT64)GetProcAddress(hL, "NetGameDistUpdate");
    p[493] = (UINT64)GetProcAddress(hL, "NetGameLinkCallback");
    p[494] = (UINT64)GetProcAddress(hL, "NetGameLinkControl");
    p[495] = (UINT64)GetProcAddress(hL, "NetGameLinkCreate");
    p[496] = (UINT64)GetProcAddress(hL, "NetGameLinkCreateStream");
    p[497] = (UINT64)GetProcAddress(hL, "NetGameLinkDestroy");
    p[498] = (UINT64)GetProcAddress(hL, "NetGameLinkDestroyStream");
    p[499] = (UINT64)GetProcAddress(hL, "NetGameLinkPeek");
    p[500] = (UINT64)GetProcAddress(hL, "NetGameLinkPeek2");
    p[501] = (UINT64)GetProcAddress(hL, "NetGameLinkRecv");
    p[502] = (UINT64)GetProcAddress(hL, "NetGameLinkRecv2");
    p[503] = (UINT64)GetProcAddress(hL, "NetGameLinkSend");
    p[504] = (UINT64)GetProcAddress(hL, "NetGameLinkStatus");
    p[505] = (UINT64)GetProcAddress(hL, "NetGameLinkUpdate");
    p[506] = (UINT64)GetProcAddress(hL, "NetGameUtilAdvert");
    p[507] = (UINT64)GetProcAddress(hL, "NetGameUtilComplete");
    p[508] = (UINT64)GetProcAddress(hL, "NetGameUtilConnect");
    p[509] = (UINT64)GetProcAddress(hL, "NetGameUtilControl");
    p[510] = (UINT64)GetProcAddress(hL, "NetGameUtilCreate");
    p[511] = (UINT64)GetProcAddress(hL, "NetGameUtilDestroy");
    p[512] = (UINT64)GetProcAddress(hL, "NetGameUtilLocate");
    p[513] = (UINT64)GetProcAddress(hL, "NetGameUtilQuery");
    p[514] = (UINT64)GetProcAddress(hL, "NetGameUtilReset");
    p[515] = (UINT64)GetProcAddress(hL, "NetGameUtilStatus");
    p[516] = (UINT64)GetProcAddress(hL, "NetGameUtilWithdraw");
    p[517] = (UINT64)GetProcAddress(hL, "NetHash");
    p[518] = (UINT64)GetProcAddress(hL, "NetHashBin");
    p[519] = (UINT64)GetProcAddress(hL, "NetIdleAdd");
    p[520] = (UINT64)GetProcAddress(hL, "NetIdleCall");
    p[521] = (UINT64)GetProcAddress(hL, "NetIdleDel");
    p[522] = (UINT64)GetProcAddress(hL, "NetIdleDone");
    p[523] = (UINT64)GetProcAddress(hL, "NetIdleReset");
    p[524] = (UINT64)GetProcAddress(hL, "NetLibCreate");
    p[525] = (UINT64)GetProcAddress(hL, "NetLibDestroy");
    p[526] = (UINT64)GetProcAddress(hL, "NetRand");
    p[527] = (UINT64)GetProcAddress(hL, "NetResourceCache");
    p[528] = (UINT64)GetProcAddress(hL, "NetResourceCacheCheck");
    p[529] = (UINT64)GetProcAddress(hL, "NetResourceCancel");
    p[530] = (UINT64)GetProcAddress(hL, "NetResourceCreate");
    p[531] = (UINT64)GetProcAddress(hL, "NetResourceDestroy");
    p[532] = (UINT64)GetProcAddress(hL, "NetResourceFetch");
    p[533] = (UINT64)GetProcAddress(hL, "NetResourceFetchString");
    p[534] = (UINT64)GetProcAddress(hL, "NetTick");
    p[535] = (UINT64)GetProcAddress(hL, "PingManagerCancelRequest");
    p[536] = (UINT64)GetProcAddress(hL, "PingManagerCancelServerRequest");
    p[537] = (UINT64)GetProcAddress(hL, "PingManagerCreate");
    p[538] = (UINT64)GetProcAddress(hL, "PingManagerDestroy");
    p[539] = (UINT64)GetProcAddress(hL, "PingManagerInvalidateAddress");
    p[540] = (UINT64)GetProcAddress(hL, "PingManagerInvalidateCache");
    p[541] = (UINT64)GetProcAddress(hL, "PingManagerPingAddress");
    p[542] = (UINT64)GetProcAddress(hL, "PingManagerPingServer");
    p[543] = (UINT64)GetProcAddress(hL, "PingManagerPingServer2");
    p[544] = (UINT64)GetProcAddress(hL, "PingManagerUpdate");
    p[545] = (UINT64)GetProcAddress(hL, "ProtoAdvtAnnounce");
    p[546] = (UINT64)GetProcAddress(hL, "ProtoAdvtCancel");
    p[547] = (UINT64)GetProcAddress(hL, "ProtoAdvtConstruct");
    p[548] = (UINT64)GetProcAddress(hL, "ProtoAdvtDestroy");
    p[549] = (UINT64)GetProcAddress(hL, "ProtoAdvtLocate");
    p[550] = (UINT64)GetProcAddress(hL, "ProtoAdvtQuery");
    p[551] = (UINT64)GetProcAddress(hL, "ProtoAriesConnect");
    p[552] = (UINT64)GetProcAddress(hL, "ProtoAriesCreate");
    p[553] = (UINT64)GetProcAddress(hL, "ProtoAriesDestroy");
    p[554] = (UINT64)GetProcAddress(hL, "ProtoAriesListen");
    p[555] = (UINT64)GetProcAddress(hL, "ProtoAriesPeek");
    p[556] = (UINT64)GetProcAddress(hL, "ProtoAriesRecv");
    p[557] = (UINT64)GetProcAddress(hL, "ProtoAriesSecure");
    p[558] = (UINT64)GetProcAddress(hL, "ProtoAriesSend");
    p[559] = (UINT64)GetProcAddress(hL, "ProtoAriesSetKey");
    p[560] = (UINT64)GetProcAddress(hL, "ProtoAriesStatus");
    p[561] = (UINT64)GetProcAddress(hL, "ProtoAriesTick");
    p[562] = (UINT64)GetProcAddress(hL, "ProtoAriesUnconnect");
    p[563] = (UINT64)GetProcAddress(hL, "ProtoAriesUnlisten");
    p[564] = (UINT64)GetProcAddress(hL, "ProtoAriesUpdate");
    p[565] = (UINT64)GetProcAddress(hL, "ProtoHttpAbort");
    p[566] = (UINT64)GetProcAddress(hL, "ProtoHttpCallback");
    p[567] = (UINT64)GetProcAddress(hL, "ProtoHttpCheckKeepAlive");
    p[568] = (UINT64)GetProcAddress(hL, "ProtoHttpClrCACerts");
    p[569] = (UINT64)GetProcAddress(hL, "ProtoHttpControl");
    p[570] = (UINT64)GetProcAddress(hL, "ProtoHttpCreate");
    p[571] = (UINT64)GetProcAddress(hL, "ProtoHttpDelete");
    p[572] = (UINT64)GetProcAddress(hL, "ProtoHttpDestroy");
    p[573] = (UINT64)GetProcAddress(hL, "ProtoHttpExtractHeaderValue");
    p[574] = (UINT64)GetProcAddress(hL, "ProtoHttpFindHeaderValue");
    p[575] = (UINT64)GetProcAddress(hL, "ProtoHttpGet");
    p[576] = (UINT64)GetProcAddress(hL, "ProtoHttpGetHeaderValue");
    p[577] = (UINT64)GetProcAddress(hL, "ProtoHttpGetLocationHeader");
    p[578] = (UINT64)GetProcAddress(hL, "ProtoHttpGetNextHeader");
    p[579] = (UINT64)GetProcAddress(hL, "ProtoHttpOptions");
    p[580] = (UINT64)GetProcAddress(hL, "ProtoHttpParseHeaderCode");
    p[581] = (UINT64)GetProcAddress(hL, "ProtoHttpPost");
    p[582] = (UINT64)GetProcAddress(hL, "ProtoHttpRecv");
    p[583] = (UINT64)GetProcAddress(hL, "ProtoHttpRecvAll");
    p[584] = (UINT64)GetProcAddress(hL, "ProtoHttpRequestCb");
    p[585] = (UINT64)GetProcAddress(hL, "ProtoHttpSend");
    p[586] = (UINT64)GetProcAddress(hL, "ProtoHttpServCallback");
    p[587] = (UINT64)GetProcAddress(hL, "ProtoHttpServControl");
    p[588] = (UINT64)GetProcAddress(hL, "ProtoHttpServCreate");
    p[589] = (UINT64)GetProcAddress(hL, "ProtoHttpServDestroy");
    p[590] = (UINT64)GetProcAddress(hL, "ProtoHttpServStatus");
    p[591] = (UINT64)GetProcAddress(hL, "ProtoHttpServUpdate");
    p[592] = (UINT64)GetProcAddress(hL, "ProtoHttpSetBaseUrl");
    p[593] = (UINT64)GetProcAddress(hL, "ProtoHttpSetCACert");
    p[594] = (UINT64)GetProcAddress(hL, "ProtoHttpSetCACert2");
    p[595] = (UINT64)GetProcAddress(hL, "ProtoHttpStatus");
    p[596] = (UINT64)GetProcAddress(hL, "ProtoHttpUpdate");
    p[597] = (UINT64)GetProcAddress(hL, "ProtoHttpUrlEncodeIntParm");
    p[598] = (UINT64)GetProcAddress(hL, "ProtoHttpUrlEncodeStrParm");
    p[599] = (UINT64)GetProcAddress(hL, "ProtoHttpUrlEncodeStrParm2");
    p[600] = (UINT64)GetProcAddress(hL, "ProtoHttpUrlParse");
    p[601] = (UINT64)GetProcAddress(hL, "ProtoHttpUrlParse2");
    p[602] = (UINT64)GetProcAddress(hL, "ProtoHttpValidateAllCA");
    p[603] = (UINT64)GetProcAddress(hL, "ProtoMangleComplete");
    p[604] = (UINT64)GetProcAddress(hL, "ProtoMangleConnect");
    p[605] = (UINT64)GetProcAddress(hL, "ProtoMangleConnect2");
    p[606] = (UINT64)GetProcAddress(hL, "ProtoMangleConnectSocket");
    p[607] = (UINT64)GetProcAddress(hL, "ProtoMangleControl");
    p[608] = (UINT64)GetProcAddress(hL, "ProtoMangleCreate");
    p[609] = (UINT64)GetProcAddress(hL, "ProtoMangleDestroy");
    p[610] = (UINT64)GetProcAddress(hL, "ProtoMangleReport");
    p[611] = (UINT64)GetProcAddress(hL, "ProtoMangleStatus");
    p[612] = (UINT64)GetProcAddress(hL, "ProtoMangleUpdate");
    p[613] = (UINT64)GetProcAddress(hL, "ProtoNameAsync");
    p[614] = (UINT64)GetProcAddress(hL, "ProtoNameSync");
    p[615] = (UINT64)GetProcAddress(hL, "ProtoPingControl");
    p[616] = (UINT64)GetProcAddress(hL, "ProtoPingCreate");
    p[617] = (UINT64)GetProcAddress(hL, "ProtoPingDestroy");
    p[618] = (UINT64)GetProcAddress(hL, "ProtoPingRequest");
    p[619] = (UINT64)GetProcAddress(hL, "ProtoPingRequestServer");
    p[620] = (UINT64)GetProcAddress(hL, "ProtoPingResponse");
    p[621] = (UINT64)GetProcAddress(hL, "ProtoSSLAccept");
    p[622] = (UINT64)GetProcAddress(hL, "ProtoSSLBind");
    p[623] = (UINT64)GetProcAddress(hL, "ProtoSSLClrCACerts");
    p[624] = (UINT64)GetProcAddress(hL, "ProtoSSLConnect");
    p[625] = (UINT64)GetProcAddress(hL, "ProtoSSLControl");
    p[626] = (UINT64)GetProcAddress(hL, "ProtoSSLCreate");
    p[627] = (UINT64)GetProcAddress(hL, "ProtoSSLDestroy");
    p[628] = (UINT64)GetProcAddress(hL, "ProtoSSLDisconnect");
    p[629] = (UINT64)GetProcAddress(hL, "ProtoSSLListen");
    p[630] = (UINT64)GetProcAddress(hL, "ProtoSSLRecv");
    p[631] = (UINT64)GetProcAddress(hL, "ProtoSSLReset");
    p[632] = (UINT64)GetProcAddress(hL, "ProtoSSLSend");
    p[633] = (UINT64)GetProcAddress(hL, "ProtoSSLSetCACert");
    p[634] = (UINT64)GetProcAddress(hL, "ProtoSSLSetCACert2");
    p[635] = (UINT64)GetProcAddress(hL, "ProtoSSLShutdown");
    p[636] = (UINT64)GetProcAddress(hL, "ProtoSSLStartup");
    p[637] = (UINT64)GetProcAddress(hL, "ProtoSSLStat");
    p[638] = (UINT64)GetProcAddress(hL, "ProtoSSLUpdate");
    p[639] = (UINT64)GetProcAddress(hL, "ProtoSSLValidateAllCA");
    p[640] = (UINT64)GetProcAddress(hL, "ProtoStreamClose");
    p[641] = (UINT64)GetProcAddress(hL, "ProtoStreamControl");
    p[642] = (UINT64)GetProcAddress(hL, "ProtoStreamCreate");
    p[643] = (UINT64)GetProcAddress(hL, "ProtoStreamDestroy");
    p[644] = (UINT64)GetProcAddress(hL, "ProtoStreamOpen");
    p[645] = (UINT64)GetProcAddress(hL, "ProtoStreamPause");
    p[646] = (UINT64)GetProcAddress(hL, "ProtoStreamRead");
    p[647] = (UINT64)GetProcAddress(hL, "ProtoStreamSetCallback");
    p[648] = (UINT64)GetProcAddress(hL, "ProtoStreamSetHttpCallback");
    p[649] = (UINT64)GetProcAddress(hL, "ProtoStreamStatus");
    p[650] = (UINT64)GetProcAddress(hL, "ProtoStreamUpdate");
    p[651] = (UINT64)GetProcAddress(hL, "ProtoTunnelAlloc");
    p[652] = (UINT64)GetProcAddress(hL, "ProtoTunnelCallback");
    p[653] = (UINT64)GetProcAddress(hL, "ProtoTunnelControl");
    p[654] = (UINT64)GetProcAddress(hL, "ProtoTunnelCreate");
    p[655] = (UINT64)GetProcAddress(hL, "ProtoTunnelDestroy");
    p[656] = (UINT64)GetProcAddress(hL, "ProtoTunnelFree");
    p[657] = (UINT64)GetProcAddress(hL, "ProtoTunnelFree2");
    p[658] = (UINT64)GetProcAddress(hL, "ProtoTunnelRawSendto");
    p[659] = (UINT64)GetProcAddress(hL, "ProtoTunnelStatus");
    p[660] = (UINT64)GetProcAddress(hL, "ProtoTunnelUpdate");
    p[661] = (UINT64)GetProcAddress(hL, "ProtoTunnelUpdatePortList");
    p[662] = (UINT64)GetProcAddress(hL, "ProtoUdpBind");
    p[663] = (UINT64)GetProcAddress(hL, "ProtoUdpConnect");
    p[664] = (UINT64)GetProcAddress(hL, "ProtoUdpCreate");
    p[665] = (UINT64)GetProcAddress(hL, "ProtoUdpDestroy");
    p[666] = (UINT64)GetProcAddress(hL, "ProtoUdpDisconnect");
    p[667] = (UINT64)GetProcAddress(hL, "ProtoUdpGetLocalAddr");
    p[668] = (UINT64)GetProcAddress(hL, "ProtoUdpRecvFrom");
    p[669] = (UINT64)GetProcAddress(hL, "ProtoUdpSend");
    p[670] = (UINT64)GetProcAddress(hL, "ProtoUdpSendTo");
    p[671] = (UINT64)GetProcAddress(hL, "ProtoUdpUpdate");
    p[672] = (UINT64)GetProcAddress(hL, "ProtoUpnpControl");
    p[673] = (UINT64)GetProcAddress(hL, "ProtoUpnpCreate");
    p[674] = (UINT64)GetProcAddress(hL, "ProtoUpnpDestroy");
    p[675] = (UINT64)GetProcAddress(hL, "ProtoUpnpGetRef");
    p[676] = (UINT64)GetProcAddress(hL, "ProtoUpnpStatus");
    p[677] = (UINT64)GetProcAddress(hL, "ProtoUpnpUpdate");
    p[678] = (UINT64)GetProcAddress(hL, "ProtoWebSocketAccept");
    p[679] = (UINT64)GetProcAddress(hL, "ProtoWebSocketConnect");
    p[680] = (UINT64)GetProcAddress(hL, "ProtoWebSocketConnect2");
    p[681] = (UINT64)GetProcAddress(hL, "ProtoWebSocketControl");
    p[682] = (UINT64)GetProcAddress(hL, "ProtoWebSocketCreate");
    p[683] = (UINT64)GetProcAddress(hL, "ProtoWebSocketCreate2");
    p[684] = (UINT64)GetProcAddress(hL, "ProtoWebSocketDestroy");
    p[685] = (UINT64)GetProcAddress(hL, "ProtoWebSocketDisconnect");
    p[686] = (UINT64)GetProcAddress(hL, "ProtoWebSocketListen");
    p[687] = (UINT64)GetProcAddress(hL, "ProtoWebSocketRecv");
    p[688] = (UINT64)GetProcAddress(hL, "ProtoWebSocketSend");
    p[689] = (UINT64)GetProcAddress(hL, "ProtoWebSocketStatus");
    p[690] = (UINT64)GetProcAddress(hL, "ProtoWebSocketUpdate");
    p[691] = (UINT64)GetProcAddress(hL, "QosApiCancelRequest");
    p[692] = (UINT64)GetProcAddress(hL, "QosApiControl");
    p[693] = (UINT64)GetProcAddress(hL, "QosApiCreate");
    p[694] = (UINT64)GetProcAddress(hL, "QosApiDestroy");
    p[695] = (UINT64)GetProcAddress(hL, "QosApiGetNatType");
    p[696] = (UINT64)GetProcAddress(hL, "QosApiListen");
    p[697] = (UINT64)GetProcAddress(hL, "QosApiRequest");
    p[698] = (UINT64)GetProcAddress(hL, "QosApiServiceRequest");
    p[699] = (UINT64)GetProcAddress(hL, "QosApiStatus");
    p[700] = (UINT64)GetProcAddress(hL, "SockaddrCompare");
    p[701] = (UINT64)GetProcAddress(hL, "SockaddrInGetAddrText");
    p[702] = (UINT64)GetProcAddress(hL, "SockaddrInParse");
    p[703] = (UINT64)GetProcAddress(hL, "SockaddrInParse2");
    p[704] = (UINT64)GetProcAddress(hL, "SockaddrInSetAddrText");
    p[705] = (UINT64)GetProcAddress(hL, "SocketAccept");
    p[706] = (UINT64)GetProcAddress(hL, "SocketBind");
    p[707] = (UINT64)GetProcAddress(hL, "SocketCallback");
    p[708] = (UINT64)GetProcAddress(hL, "SocketClose");
    p[709] = (UINT64)GetProcAddress(hL, "SocketConnect");
    p[710] = (UINT64)GetProcAddress(hL, "SocketControl");
    p[711] = (UINT64)GetProcAddress(hL, "SocketCreate");
    p[712] = (UINT64)GetProcAddress(hL, "SocketDestroy");
    p[713] = (UINT64)GetProcAddress(hL, "SocketGetLocalAddr");
    p[714] = (UINT64)GetProcAddress(hL, "SocketHost");
    p[715] = (UINT64)GetProcAddress(hL, "SocketHtonl");
    p[716] = (UINT64)GetProcAddress(hL, "SocketHtons");
    p[717] = (UINT64)GetProcAddress(hL, "SocketImport");
    p[718] = (UINT64)GetProcAddress(hL, "SocketInAddrGetText");
    p[719] = (UINT64)GetProcAddress(hL, "SocketInTextGetAddr");
    p[720] = (UINT64)GetProcAddress(hL, "SocketInfo");
    p[721] = (UINT64)GetProcAddress(hL, "SocketListen");
    p[722] = (UINT64)GetProcAddress(hL, "SocketLookup");
    p[723] = (UINT64)GetProcAddress(hL, "SocketNtohl");
    p[724] = (UINT64)GetProcAddress(hL, "SocketNtohs");
    p[725] = (UINT64)GetProcAddress(hL, "SocketOpen");
    p[726] = (UINT64)GetProcAddress(hL, "SocketRecvfrom");
    p[727] = (UINT64)GetProcAddress(hL, "SocketRelease");
    p[728] = (UINT64)GetProcAddress(hL, "SocketSendto");
    p[729] = (UINT64)GetProcAddress(hL, "SocketShutdown");
    p[730] = (UINT64)GetProcAddress(hL, "TagFieldDelete");
    p[731] = (UINT64)GetProcAddress(hL, "TagFieldDivider");
    p[732] = (UINT64)GetProcAddress(hL, "TagFieldDupl");
    p[733] = (UINT64)GetProcAddress(hL, "TagFieldFind");
    p[734] = (UINT64)GetProcAddress(hL, "TagFieldFind2");
    p[735] = (UINT64)GetProcAddress(hL, "TagFieldFindIdx");
    p[736] = (UINT64)GetProcAddress(hL, "TagFieldFindNext");
    p[737] = (UINT64)GetProcAddress(hL, "TagFieldFirst");
    p[738] = (UINT64)GetProcAddress(hL, "TagFieldFormat");
    p[739] = (UINT64)GetProcAddress(hL, "TagFieldGetAddress");
    p[740] = (UINT64)GetProcAddress(hL, "TagFieldGetBinary");
    p[741] = (UINT64)GetProcAddress(hL, "TagFieldGetDate");
    p[742] = (UINT64)GetProcAddress(hL, "TagFieldGetDelim");
    p[743] = (UINT64)GetProcAddress(hL, "TagFieldGetEpoch");
    p[744] = (UINT64)GetProcAddress(hL, "TagFieldGetFlags");
    p[745] = (UINT64)GetProcAddress(hL, "TagFieldGetFloat");
    p[746] = (UINT64)GetProcAddress(hL, "TagFieldGetNumber");
    p[747] = (UINT64)GetProcAddress(hL, "TagFieldGetNumber64");
    p[748] = (UINT64)GetProcAddress(hL, "TagFieldGetRaw");
    p[749] = (UINT64)GetProcAddress(hL, "TagFieldGetString");
    p[750] = (UINT64)GetProcAddress(hL, "TagFieldGetStructure");
    p[751] = (UINT64)GetProcAddress(hL, "TagFieldGetStructureOffsets");
    p[752] = (UINT64)GetProcAddress(hL, "TagFieldGetToken");
    p[753] = (UINT64)GetProcAddress(hL, "TagFieldMerge");
    p[754] = (UINT64)GetProcAddress(hL, "TagFieldPrintf");
    p[755] = (UINT64)GetProcAddress(hL, "TagFieldRename");
    p[756] = (UINT64)GetProcAddress(hL, "TagFieldSetAddress");
    p[757] = (UINT64)GetProcAddress(hL, "TagFieldSetBinary");
    p[758] = (UINT64)GetProcAddress(hL, "TagFieldSetBinary7");
    p[759] = (UINT64)GetProcAddress(hL, "TagFieldSetDate");
    p[760] = (UINT64)GetProcAddress(hL, "TagFieldSetEpoch");
    p[761] = (UINT64)GetProcAddress(hL, "TagFieldSetFlags");
    p[762] = (UINT64)GetProcAddress(hL, "TagFieldSetFloat");
    p[763] = (UINT64)GetProcAddress(hL, "TagFieldSetNumber");
    p[764] = (UINT64)GetProcAddress(hL, "TagFieldSetNumber64");
    p[765] = (UINT64)GetProcAddress(hL, "TagFieldSetRaw");
    p[766] = (UINT64)GetProcAddress(hL, "TagFieldSetString");
    p[767] = (UINT64)GetProcAddress(hL, "TagFieldSetStructure");
    p[768] = (UINT64)GetProcAddress(hL, "TagFieldSetToken");
    p[769] = (UINT64)GetProcAddress(hL, "Utf8DecodeToUCS2");
    p[770] = (UINT64)GetProcAddress(hL, "Utf8EncodeFrom8Bit");
    p[771] = (UINT64)GetProcAddress(hL, "Utf8EncodeFromUCS2");
    p[772] = (UINT64)GetProcAddress(hL, "Utf8EncodeFromUCS2CodePt");
    p[773] = (UINT64)GetProcAddress(hL, "Utf8Replace");
    p[774] = (UINT64)GetProcAddress(hL, "Utf8StrLen");
    p[775] = (UINT64)GetProcAddress(hL, "Utf8Strip");
    p[776] = (UINT64)GetProcAddress(hL, "Utf8TranslateTo8Bit");
    p[777] = (UINT64)GetProcAddress(hL, "VoipCodecControl");
    p[778] = (UINT64)GetProcAddress(hL, "VoipCodecCreate");
    p[779] = (UINT64)GetProcAddress(hL, "VoipCodecDecode");
    p[780] = (UINT64)GetProcAddress(hL, "VoipCodecDestroy");
    p[781] = (UINT64)GetProcAddress(hL, "VoipCodecEncode");
    p[782] = (UINT64)GetProcAddress(hL, "VoipCodecRegister");
    p[783] = (UINT64)GetProcAddress(hL, "VoipCodecReset");
    p[784] = (UINT64)GetProcAddress(hL, "VoipCodecStatus");
    p[785] = (UINT64)GetProcAddress(hL, "VoipConnect");
    p[786] = (UINT64)GetProcAddress(hL, "VoipControl");
    p[787] = (UINT64)GetProcAddress(hL, "VoipDisconnect");
    p[788] = (UINT64)GetProcAddress(hL, "VoipDisconnect2");
    p[789] = (UINT64)GetProcAddress(hL, "VoipGetProfileStat");
    p[790] = (UINT64)GetProcAddress(hL, "VoipGetProfileTime");
    p[791] = (UINT64)GetProcAddress(hL, "VoipGetRef");
    p[792] = (UINT64)GetProcAddress(hL, "VoipGroupConnect");
    p[793] = (UINT64)GetProcAddress(hL, "VoipGroupControl");
    p[794] = (UINT64)GetProcAddress(hL, "VoipGroupCreate");
    p[795] = (UINT64)GetProcAddress(hL, "VoipGroupDestroy");
    p[796] = (UINT64)GetProcAddress(hL, "VoipGroupDisconnect");
    p[797] = (UINT64)GetProcAddress(hL, "VoipGroupIsMutedByClientId");
    p[798] = (UINT64)GetProcAddress(hL, "VoipGroupIsMutedByConnId");
    p[799] = (UINT64)GetProcAddress(hL, "VoipGroupLocal");
    p[800] = (UINT64)GetProcAddress(hL, "VoipGroupMuteByClientId");
    p[801] = (UINT64)GetProcAddress(hL, "VoipGroupMuteByConnId");
    p[802] = (UINT64)GetProcAddress(hL, "VoipGroupRemote");
    p[803] = (UINT64)GetProcAddress(hL, "VoipGroupResume");
    p[804] = (UINT64)GetProcAddress(hL, "VoipGroupSetConnSharingEventCallback");
    p[805] = (UINT64)GetProcAddress(hL, "VoipGroupSetEventCallback");
    p[806] = (UINT64)GetProcAddress(hL, "VoipGroupStatus");
    p[807] = (UINT64)GetProcAddress(hL, "VoipGroupSuspend");
    p[808] = (UINT64)GetProcAddress(hL, "VoipLocal");
    p[809] = (UINT64)GetProcAddress(hL, "VoipMicrophone");
    p[810] = (UINT64)GetProcAddress(hL, "VoipRemote");
    p[811] = (UINT64)GetProcAddress(hL, "VoipRemove");
    p[812] = (UINT64)GetProcAddress(hL, "VoipResetChannels");
    p[813] = (UINT64)GetProcAddress(hL, "VoipSelectChannel");
    p[814] = (UINT64)GetProcAddress(hL, "VoipSetEventCallback");
    p[815] = (UINT64)GetProcAddress(hL, "VoipSetLocalUser");
    p[816] = (UINT64)GetProcAddress(hL, "VoipShutdown");
    p[817] = (UINT64)GetProcAddress(hL, "VoipSpeaker");
    p[818] = (UINT64)GetProcAddress(hL, "VoipSpkrCallback");
    p[819] = (UINT64)GetProcAddress(hL, "VoipStartup");
    p[820] = (UINT64)GetProcAddress(hL, "VoipStatus");
    p[821] = (UINT64)GetProcAddress(hL, "VoipTunnelCallback");
    p[822] = (UINT64)GetProcAddress(hL, "VoipTunnelClientListAdd");
    p[823] = (UINT64)GetProcAddress(hL, "VoipTunnelClientListAdd2");
    p[824] = (UINT64)GetProcAddress(hL, "VoipTunnelClientListDel");
    p[825] = (UINT64)GetProcAddress(hL, "VoipTunnelClientListMatchAddr");
    p[826] = (UINT64)GetProcAddress(hL, "VoipTunnelClientListMatchFunc");
    p[827] = (UINT64)GetProcAddress(hL, "VoipTunnelClientListMatchId");
    p[828] = (UINT64)GetProcAddress(hL, "VoipTunnelClientListMatchIndex");
    p[829] = (UINT64)GetProcAddress(hL, "VoipTunnelClientListMatchSockaddr");
    p[830] = (UINT64)GetProcAddress(hL, "VoipTunnelClientRefreshSendMask");
    p[831] = (UINT64)GetProcAddress(hL, "VoipTunnelControl");
    p[832] = (UINT64)GetProcAddress(hL, "VoipTunnelCreate");
    p[833] = (UINT64)GetProcAddress(hL, "VoipTunnelDestroy");
    p[834] = (UINT64)GetProcAddress(hL, "VoipTunnelGameListAdd");
    p[835] = (UINT64)GetProcAddress(hL, "VoipTunnelGameListDel");
    p[836] = (UINT64)GetProcAddress(hL, "VoipTunnelStatus");
    p[837] = (UINT64)GetProcAddress(hL, "VoipTunnelUpdate");
    p[838] = (UINT64)GetProcAddress(hL, "WebLogConfigure");
    p[839] = (UINT64)GetProcAddress(hL, "WebLogControl");
    p[840] = (UINT64)GetProcAddress(hL, "WebLogCreate");
    p[841] = (UINT64)GetProcAddress(hL, "WebLogDebugHook");
    p[842] = (UINT64)GetProcAddress(hL, "WebLogDestroy");
    p[843] = (UINT64)GetProcAddress(hL, "WebLogPrintf");
    p[844] = (UINT64)GetProcAddress(hL, "WebLogStart");
    p[845] = (UINT64)GetProcAddress(hL, "WebLogStop");
    p[846] = (UINT64)GetProcAddress(hL, "WebLogUpdate");
    p[847] = (UINT64)GetProcAddress(hL, "WebOfferAction");
    p[848] = (UINT64)GetProcAddress(hL, "WebOfferClear");
    p[849] = (UINT64)GetProcAddress(hL, "WebOfferCommand");
    p[850] = (UINT64)GetProcAddress(hL, "WebOfferCreate");
    p[851] = (UINT64)GetProcAddress(hL, "WebOfferDestroy");
    p[852] = (UINT64)GetProcAddress(hL, "WebOfferExecute");
    p[853] = (UINT64)GetProcAddress(hL, "WebOfferGetAlert");
    p[854] = (UINT64)GetProcAddress(hL, "WebOfferGetArticles");
    p[855] = (UINT64)GetProcAddress(hL, "WebOfferGetBusy");
    p[856] = (UINT64)GetProcAddress(hL, "WebOfferGetBusy2");
    p[857] = (UINT64)GetProcAddress(hL, "WebOfferGetCredit");
    p[858] = (UINT64)GetProcAddress(hL, "WebOfferGetForm");
    p[859] = (UINT64)GetProcAddress(hL, "WebOfferGetMarketplace");
    p[860] = (UINT64)GetProcAddress(hL, "WebOfferGetMedia");
    p[861] = (UINT64)GetProcAddress(hL, "WebOfferGetMenu");
    p[862] = (UINT64)GetProcAddress(hL, "WebOfferGetNews");
    p[863] = (UINT64)GetProcAddress(hL, "WebOfferGetPromo");
    p[864] = (UINT64)GetProcAddress(hL, "WebOfferGetStory");
    p[865] = (UINT64)GetProcAddress(hL, "WebOfferHttp");
    p[866] = (UINT64)GetProcAddress(hL, "WebOfferHttpComplete");
    p[867] = (UINT64)GetProcAddress(hL, "WebOfferParamList");
    p[868] = (UINT64)GetProcAddress(hL, "WebOfferResource");
    p[869] = (UINT64)GetProcAddress(hL, "WebOfferResultData");
    p[870] = (UINT64)GetProcAddress(hL, "WebOfferSetCredit");
    p[871] = (UINT64)GetProcAddress(hL, "WebOfferSetForm");
    p[872] = (UINT64)GetProcAddress(hL, "WebOfferSetPromo");
    p[873] = (UINT64)GetProcAddress(hL, "WebOfferSetup");
    p[874] = (UINT64)GetProcAddress(hL, "WebOfferUpdate");
    p[875] = (UINT64)GetProcAddress(hL, "XmlAttrSetAddr");
    p[876] = (UINT64)GetProcAddress(hL, "XmlAttrSetDate");
    p[877] = (UINT64)GetProcAddress(hL, "XmlAttrSetFloat");
    p[878] = (UINT64)GetProcAddress(hL, "XmlAttrSetInt");
    p[879] = (UINT64)GetProcAddress(hL, "XmlAttrSetString");
    p[880] = (UINT64)GetProcAddress(hL, "XmlAttrSetStringRaw");
    p[881] = (UINT64)GetProcAddress(hL, "XmlAttribGetDate");
    p[882] = (UINT64)GetProcAddress(hL, "XmlAttribGetInteger");
    p[883] = (UINT64)GetProcAddress(hL, "XmlAttribGetString");
    p[884] = (UINT64)GetProcAddress(hL, "XmlAttribGetToken");
    p[885] = (UINT64)GetProcAddress(hL, "XmlBufSizeIncrease");
    p[886] = (UINT64)GetProcAddress(hL, "XmlComplete");
    p[887] = (UINT64)GetProcAddress(hL, "XmlContentGetAddress");
    p[888] = (UINT64)GetProcAddress(hL, "XmlContentGetBinary");
    p[889] = (UINT64)GetProcAddress(hL, "XmlContentGetDate");
    p[890] = (UINT64)GetProcAddress(hL, "XmlContentGetInteger");
    p[891] = (UINT64)GetProcAddress(hL, "XmlContentGetString");
    p[892] = (UINT64)GetProcAddress(hL, "XmlContentGetToken");
    p[893] = (UINT64)GetProcAddress(hL, "XmlConvEpoch2Date");
    p[894] = (UINT64)GetProcAddress(hL, "XmlElemAddDate");
    p[895] = (UINT64)GetProcAddress(hL, "XmlElemAddFloat");
    p[896] = (UINT64)GetProcAddress(hL, "XmlElemAddInt");
    p[897] = (UINT64)GetProcAddress(hL, "XmlElemAddString");
    p[898] = (UINT64)GetProcAddress(hL, "XmlElemSetAddr");
    p[899] = (UINT64)GetProcAddress(hL, "XmlElemSetDate");
    p[900] = (UINT64)GetProcAddress(hL, "XmlElemSetInt");
    p[901] = (UINT64)GetProcAddress(hL, "XmlElemSetString");
    p[902] = (UINT64)GetProcAddress(hL, "XmlElemSetStringRaw");
    p[903] = (UINT64)GetProcAddress(hL, "XmlFind");
    p[904] = (UINT64)GetProcAddress(hL, "XmlFinish");
    p[905] = (UINT64)GetProcAddress(hL, "XmlFormatPrintf");
    p[906] = (UINT64)GetProcAddress(hL, "XmlFormatVPrintf");
    p[907] = (UINT64)GetProcAddress(hL, "XmlInit");
    p[908] = (UINT64)GetProcAddress(hL, "XmlNext");
    p[909] = (UINT64)GetProcAddress(hL, "XmlSkip");
    p[910] = (UINT64)GetProcAddress(hL, "XmlStep");
    p[911] = (UINT64)GetProcAddress(hL, "XmlTagEnd");
    p[912] = (UINT64)GetProcAddress(hL, "XmlTagStart");
    p[913] = (UINT64)GetProcAddress(hL, "XmlValidate");
    p[914] = (UINT64)GetProcAddress(hL, "_BuddyApiSetTalkToXbox");
    p[915] = (UINT64)GetProcAddress(hL, "ds_localtime");
    p[916] = (UINT64)GetProcAddress(hL, "ds_plattimetotime");
    p[917] = (UINT64)GetProcAddress(hL, "ds_plattimetotimems");
    p[918] = (UINT64)GetProcAddress(hL, "ds_secstostr");
    p[919] = (UINT64)GetProcAddress(hL, "ds_secstotime");
    p[920] = (UINT64)GetProcAddress(hL, "ds_snzprintf");
    p[921] = (UINT64)GetProcAddress(hL, "ds_strcmpwc");
    p[922] = (UINT64)GetProcAddress(hL, "ds_stricmp");
    p[923] = (UINT64)GetProcAddress(hL, "ds_stricmpwc");
    p[924] = (UINT64)GetProcAddress(hL, "ds_stristr");
    p[925] = (UINT64)GetProcAddress(hL, "ds_strnicmp");
    p[926] = (UINT64)GetProcAddress(hL, "ds_strnzcat");
    p[927] = (UINT64)GetProcAddress(hL, "ds_strnzcpy");
    p[928] = (UINT64)GetProcAddress(hL, "ds_strsubzcat");
    p[929] = (UINT64)GetProcAddress(hL, "ds_strsubzcpy");
    p[930] = (UINT64)GetProcAddress(hL, "ds_strtotime");
    p[931] = (UINT64)GetProcAddress(hL, "ds_strtotime2");
    p[932] = (UINT64)GetProcAddress(hL, "ds_timeinsecs");
    p[933] = (UINT64)GetProcAddress(hL, "ds_timetosecs");
    p[934] = (UINT64)GetProcAddress(hL, "ds_timetostr");
    p[935] = (UINT64)GetProcAddress(hL, "ds_timezone");
    p[936] = (UINT64)GetProcAddress(hL, "ds_vsnprintf");
    p[937] = (UINT64)GetProcAddress(hL, "ds_vsnzprintf");
    fprintf(Log, "Original dll and function pointers loaded.\n");
    loadPlugins(Log, ".");
    loadPlugins(Log, "asi");
    fprintf(Log, "Done.\n");
    fclose(Log);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            // attach to process
            // return FALSE to fail DLL load
            CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Start, 0, 0, 0);
            break;

        case DLL_PROCESS_DETACH:
            // detach from process
            break;

        case DLL_THREAD_ATTACH:
            // attach to thread
            break;

        case DLL_THREAD_DETACH:
            // detach from thread
            break;
    }
    return TRUE; // succesful
}

extern "C" DLL_EXPORT Base64Decode()
{
asm("jmp *p + 0 * 8\n\t");
}

extern "C" DLL_EXPORT Base64Decode2()
{
asm("jmp *p + 1 * 8\n\t");
}

extern "C" DLL_EXPORT Base64Decode3()
{
asm("jmp *p + 2 * 8\n\t");
}

extern "C" DLL_EXPORT Base64Encode()
{
asm("jmp *p + 3 * 8\n\t");
}

extern "C" DLL_EXPORT Base64Encode2()
{
asm("jmp *p + 4 * 8\n\t");
}

extern "C" DLL_EXPORT Binary7Decode()
{
asm("jmp *p + 5 * 8\n\t");
}

extern "C" DLL_EXPORT Binary7Encode()
{
asm("jmp *p + 6 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiAdd()
{
asm("jmp *p + 7 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiBroadcast()
{
asm("jmp *p + 8 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiBuddyInvite()
{
asm("jmp *p + 9 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiConfig()
{
asm("jmp *p + 10 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiConnect()
{
asm("jmp *p + 11 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiCreate2()
{
asm("jmp *p + 12 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiDebug()
{
asm("jmp *p + 13 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiDel()
{
asm("jmp *p + 14 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiDestroy()
{
asm("jmp *p + 15 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiDisconnect()
{
asm("jmp *p + 16 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiDomain()
{
asm("jmp *p + 17 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiFind()
{
asm("jmp *p + 18 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiFindUsers()
{
asm("jmp *p + 19 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiFlush()
{
asm("jmp *p + 20 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiGameInvite()
{
asm("jmp *p + 21 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiGetForwarding()
{
asm("jmp *p + 22 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiGetMyTitleName()
{
asm("jmp *p + 23 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiGetTitleName()
{
asm("jmp *p + 24 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiGetUserSessionID()
{
asm("jmp *p + 25 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiJoinGame()
{
asm("jmp *p + 26 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiPresDiff()
{
asm("jmp *p + 27 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiPresExFlags()
{
asm("jmp *p + 28 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiPresExtra()
{
asm("jmp *p + 29 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiPresInit()
{
asm("jmp *p + 30 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiPresJoinable()
{
asm("jmp *p + 31 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiPresNoText()
{
asm("jmp *p + 32 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiPresSame()
{
asm("jmp *p + 33 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiPresSend()
{
asm("jmp *p + 34 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiRecv()
{
asm("jmp *p + 35 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiRefreshTitle()
{
asm("jmp *p + 36 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiRegisterBuddyChangeCallback()
{
asm("jmp *p + 37 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiRegisterBuddyDelCallback()
{
asm("jmp *p + 38 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiResource()
{
asm("jmp *p + 39 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiRespondBuddy()
{
asm("jmp *p + 40 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiRespondGame()
{
asm("jmp *p + 41 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiResumeXDK()
{
asm("jmp *p + 42 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiRoster()
{
asm("jmp *p + 43 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiRosterList()
{
asm("jmp *p + 44 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiSend()
{
asm("jmp *p + 45 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiSetForwarding()
{
asm("jmp *p + 46 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiSetGameInviteSessionID()
{
asm("jmp *p + 47 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiStatus()
{
asm("jmp *p + 48 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiSuspendXDK()
{
asm("jmp *p + 49 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiUpdate()
{
asm("jmp *p + 50 * 8\n\t");
}

extern "C" DLL_EXPORT BuddyApiUserFound()
{
asm("jmp *p + 51 * 8\n\t");
}

extern "C" DLL_EXPORT CommSRPCallback()
{
asm("jmp *p + 52 * 8\n\t");
}

extern "C" DLL_EXPORT CommSRPConnect()
{
asm("jmp *p + 53 * 8\n\t");
}

extern "C" DLL_EXPORT CommSRPConstruct()
{
asm("jmp *p + 54 * 8\n\t");
}

extern "C" DLL_EXPORT CommSRPDestroy()
{
asm("jmp *p + 55 * 8\n\t");
}

extern "C" DLL_EXPORT CommSRPListen()
{
asm("jmp *p + 56 * 8\n\t");
}

extern "C" DLL_EXPORT CommSRPPeek()
{
asm("jmp *p + 57 * 8\n\t");
}

extern "C" DLL_EXPORT CommSRPRecv()
{
asm("jmp *p + 58 * 8\n\t");
}

extern "C" DLL_EXPORT CommSRPResolve()
{
asm("jmp *p + 59 * 8\n\t");
}

extern "C" DLL_EXPORT CommSRPSend()
{
asm("jmp *p + 60 * 8\n\t");
}

extern "C" DLL_EXPORT CommSRPStatus()
{
asm("jmp *p + 61 * 8\n\t");
}

extern "C" DLL_EXPORT CommSRPTick()
{
asm("jmp *p + 62 * 8\n\t");
}

extern "C" DLL_EXPORT CommSRPUnconnect()
{
asm("jmp *p + 63 * 8\n\t");
}

extern "C" DLL_EXPORT CommSRPUnlisten()
{
asm("jmp *p + 64 * 8\n\t");
}

extern "C" DLL_EXPORT CommSRPUnresolve()
{
asm("jmp *p + 65 * 8\n\t");
}

extern "C" DLL_EXPORT CommTAPICallback()
{
asm("jmp *p + 66 * 8\n\t");
}

extern "C" DLL_EXPORT CommTAPIConnect()
{
asm("jmp *p + 67 * 8\n\t");
}

extern "C" DLL_EXPORT CommTAPIConstruct()
{
asm("jmp *p + 68 * 8\n\t");
}

extern "C" DLL_EXPORT CommTAPIDestroy()
{
asm("jmp *p + 69 * 8\n\t");
}

extern "C" DLL_EXPORT CommTAPIListen()
{
asm("jmp *p + 70 * 8\n\t");
}

extern "C" DLL_EXPORT CommTAPIPeek()
{
asm("jmp *p + 71 * 8\n\t");
}

extern "C" DLL_EXPORT CommTAPIRecv()
{
asm("jmp *p + 72 * 8\n\t");
}

extern "C" DLL_EXPORT CommTAPIResolve()
{
asm("jmp *p + 73 * 8\n\t");
}

extern "C" DLL_EXPORT CommTAPISend()
{
asm("jmp *p + 74 * 8\n\t");
}

extern "C" DLL_EXPORT CommTAPIStatus()
{
asm("jmp *p + 75 * 8\n\t");
}

extern "C" DLL_EXPORT CommTAPITick()
{
asm("jmp *p + 76 * 8\n\t");
}

extern "C" DLL_EXPORT CommTAPIUnconnect()
{
asm("jmp *p + 77 * 8\n\t");
}

extern "C" DLL_EXPORT CommTAPIUnlisten()
{
asm("jmp *p + 78 * 8\n\t");
}

extern "C" DLL_EXPORT CommTAPIUnresolve()
{
asm("jmp *p + 79 * 8\n\t");
}

extern "C" DLL_EXPORT CommTCPCallback()
{
asm("jmp *p + 80 * 8\n\t");
}

extern "C" DLL_EXPORT CommTCPConnect()
{
asm("jmp *p + 81 * 8\n\t");
}

extern "C" DLL_EXPORT CommTCPConstruct()
{
asm("jmp *p + 82 * 8\n\t");
}

extern "C" DLL_EXPORT CommTCPDestroy()
{
asm("jmp *p + 83 * 8\n\t");
}

extern "C" DLL_EXPORT CommTCPListen()
{
asm("jmp *p + 84 * 8\n\t");
}

extern "C" DLL_EXPORT CommTCPPeek()
{
asm("jmp *p + 85 * 8\n\t");
}

extern "C" DLL_EXPORT CommTCPRecv()
{
asm("jmp *p + 86 * 8\n\t");
}

extern "C" DLL_EXPORT CommTCPResolve()
{
asm("jmp *p + 87 * 8\n\t");
}

extern "C" DLL_EXPORT CommTCPSend()
{
asm("jmp *p + 88 * 8\n\t");
}

extern "C" DLL_EXPORT CommTCPStatus()
{
asm("jmp *p + 89 * 8\n\t");
}

extern "C" DLL_EXPORT CommTCPTick()
{
asm("jmp *p + 90 * 8\n\t");
}

extern "C" DLL_EXPORT CommTCPUnconnect()
{
asm("jmp *p + 91 * 8\n\t");
}

extern "C" DLL_EXPORT CommTCPUnlisten()
{
asm("jmp *p + 92 * 8\n\t");
}

extern "C" DLL_EXPORT CommTCPUnresolve()
{
asm("jmp *p + 93 * 8\n\t");
}

extern "C" DLL_EXPORT CommUDPCallback()
{
asm("jmp *p + 94 * 8\n\t");
}

extern "C" DLL_EXPORT CommUDPConnect()
{
asm("jmp *p + 95 * 8\n\t");
}

extern "C" DLL_EXPORT CommUDPConstruct()
{
asm("jmp *p + 96 * 8\n\t");
}

extern "C" DLL_EXPORT CommUDPControl()
{
asm("jmp *p + 97 * 8\n\t");
}

extern "C" DLL_EXPORT CommUDPDestroy()
{
asm("jmp *p + 98 * 8\n\t");
}

extern "C" DLL_EXPORT CommUDPListen()
{
asm("jmp *p + 99 * 8\n\t");
}

extern "C" DLL_EXPORT CommUDPPeek()
{
asm("jmp *p + 100 * 8\n\t");
}

extern "C" DLL_EXPORT CommUDPRecv()
{
asm("jmp *p + 101 * 8\n\t");
}

extern "C" DLL_EXPORT CommUDPResolve()
{
asm("jmp *p + 102 * 8\n\t");
}

extern "C" DLL_EXPORT CommUDPSend()
{
asm("jmp *p + 103 * 8\n\t");
}

extern "C" DLL_EXPORT CommUDPStatus()
{
asm("jmp *p + 104 * 8\n\t");
}

extern "C" DLL_EXPORT CommUDPTick()
{
asm("jmp *p + 105 * 8\n\t");
}

extern "C" DLL_EXPORT CommUDPUnconnect()
{
asm("jmp *p + 106 * 8\n\t");
}

extern "C" DLL_EXPORT CommUDPUnlisten()
{
asm("jmp *p + 107 * 8\n\t");
}

extern "C" DLL_EXPORT CommUDPUnresolve()
{
asm("jmp *p + 108 * 8\n\t");
}

extern "C" DLL_EXPORT ConnApiAddCallback()
{
asm("jmp *p + 109 * 8\n\t");
}

extern "C" DLL_EXPORT ConnApiAddClient()
{
asm("jmp *p + 110 * 8\n\t");
}

extern "C" DLL_EXPORT ConnApiAddUser()
{
asm("jmp *p + 111 * 8\n\t");
}

extern "C" DLL_EXPORT ConnApiConnect()
{
asm("jmp *p + 112 * 8\n\t");
}

extern "C" DLL_EXPORT ConnApiControl()
{
asm("jmp *p + 113 * 8\n\t");
}

extern "C" DLL_EXPORT ConnApiCreate2()
{
asm("jmp *p + 114 * 8\n\t");
}

extern "C" DLL_EXPORT ConnApiDestroy()
{
asm("jmp *p + 115 * 8\n\t");
}

extern "C" DLL_EXPORT ConnApiDisconnect()
{
asm("jmp *p + 116 * 8\n\t");
}

extern "C" DLL_EXPORT ConnApiFindClient()
{
asm("jmp *p + 117 * 8\n\t");
}

extern "C" DLL_EXPORT ConnApiFindClientById()
{
asm("jmp *p + 118 * 8\n\t");
}

extern "C" DLL_EXPORT ConnApiGetClientList()
{
asm("jmp *p + 119 * 8\n\t");
}

extern "C" DLL_EXPORT ConnApiMigratePlatformHost()
{
asm("jmp *p + 120 * 8\n\t");
}

extern "C" DLL_EXPORT ConnApiMigrateTopologyHost()
{
asm("jmp *p + 121 * 8\n\t");
}

extern "C" DLL_EXPORT ConnApiOnline()
{
asm("jmp *p + 122 * 8\n\t");
}

extern "C" DLL_EXPORT ConnApiRematch()
{
asm("jmp *p + 123 * 8\n\t");
}

extern "C" DLL_EXPORT ConnApiRemoveCallback()
{
asm("jmp *p + 124 * 8\n\t");
}

extern "C" DLL_EXPORT ConnApiRemoveClient()
{
asm("jmp *p + 125 * 8\n\t");
}

extern "C" DLL_EXPORT ConnApiRemoveUser()
{
asm("jmp *p + 126 * 8\n\t");
}

extern "C" DLL_EXPORT ConnApiSetPresence()
{
asm("jmp *p + 127 * 8\n\t");
}

extern "C" DLL_EXPORT ConnApiStart()
{
asm("jmp *p + 128 * 8\n\t");
}

extern "C" DLL_EXPORT ConnApiStatus()
{
asm("jmp *p + 129 * 8\n\t");
}

extern "C" DLL_EXPORT ConnApiStatus2()
{
asm("jmp *p + 130 * 8\n\t");
}

extern "C" DLL_EXPORT ConnApiStop()
{
asm("jmp *p + 131 * 8\n\t");
}

extern "C" DLL_EXPORT ConnApiUpdate()
{
asm("jmp *p + 132 * 8\n\t");
}

extern "C" DLL_EXPORT CryptAesDecrypt()
{
asm("jmp *p + 133 * 8\n\t");
}

extern "C" DLL_EXPORT CryptAesEncrypt()
{
asm("jmp *p + 134 * 8\n\t");
}

extern "C" DLL_EXPORT CryptAesInit()
{
asm("jmp *p + 135 * 8\n\t");
}

extern "C" DLL_EXPORT CryptArc4Advance()
{
asm("jmp *p + 136 * 8\n\t");
}

extern "C" DLL_EXPORT CryptArc4Apply()
{
asm("jmp *p + 137 * 8\n\t");
}

extern "C" DLL_EXPORT CryptArc4Init()
{
asm("jmp *p + 138 * 8\n\t");
}

extern "C" DLL_EXPORT CryptArc4StringDecrypt()
{
asm("jmp *p + 139 * 8\n\t");
}

extern "C" DLL_EXPORT CryptArc4StringEncrypt()
{
asm("jmp *p + 140 * 8\n\t");
}

extern "C" DLL_EXPORT CryptArc4StringEncryptStaticCode()
{
asm("jmp *p + 141 * 8\n\t");
}

extern "C" DLL_EXPORT CryptHashGet()
{
asm("jmp *p + 142 * 8\n\t");
}

extern "C" DLL_EXPORT CryptHashGetSize()
{
asm("jmp *p + 143 * 8\n\t");
}

extern "C" DLL_EXPORT CryptHmacCalc()
{
asm("jmp *p + 144 * 8\n\t");
}

extern "C" DLL_EXPORT CryptHmacCalcMulti()
{
asm("jmp *p + 145 * 8\n\t");
}

extern "C" DLL_EXPORT CryptMD2Final()
{
asm("jmp *p + 146 * 8\n\t");
}

extern "C" DLL_EXPORT CryptMD2Init()
{
asm("jmp *p + 147 * 8\n\t");
}

extern "C" DLL_EXPORT CryptMD2Init2()
{
asm("jmp *p + 148 * 8\n\t");
}

extern "C" DLL_EXPORT CryptMD2Update()
{
asm("jmp *p + 149 * 8\n\t");
}

extern "C" DLL_EXPORT CryptMD5Final()
{
asm("jmp *p + 150 * 8\n\t");
}

extern "C" DLL_EXPORT CryptMD5Init()
{
asm("jmp *p + 151 * 8\n\t");
}

extern "C" DLL_EXPORT CryptMD5Init2()
{
asm("jmp *p + 152 * 8\n\t");
}

extern "C" DLL_EXPORT CryptMD5Update()
{
asm("jmp *p + 153 * 8\n\t");
}

extern "C" DLL_EXPORT CryptRSAEncrypt()
{
asm("jmp *p + 154 * 8\n\t");
}

extern "C" DLL_EXPORT CryptRSAInit()
{
asm("jmp *p + 155 * 8\n\t");
}

extern "C" DLL_EXPORT CryptRSAInitMaster()
{
asm("jmp *p + 156 * 8\n\t");
}

extern "C" DLL_EXPORT CryptRSAInitPrivate()
{
asm("jmp *p + 157 * 8\n\t");
}

extern "C" DLL_EXPORT CryptRSAInitSignature()
{
asm("jmp *p + 158 * 8\n\t");
}

extern "C" DLL_EXPORT CryptRandGet()
{
asm("jmp *p + 159 * 8\n\t");
}

extern "C" DLL_EXPORT CryptRandInit()
{
asm("jmp *p + 160 * 8\n\t");
}

extern "C" DLL_EXPORT CryptRandShutdown()
{
asm("jmp *p + 161 * 8\n\t");
}

extern "C" DLL_EXPORT CryptSSC2Apply()
{
asm("jmp *p + 162 * 8\n\t");
}

extern "C" DLL_EXPORT CryptSSC2Init()
{
asm("jmp *p + 163 * 8\n\t");
}

extern "C" DLL_EXPORT CryptSSC2StringDecrypt()
{
asm("jmp *p + 164 * 8\n\t");
}

extern "C" DLL_EXPORT CryptSSC2StringEncrypt()
{
asm("jmp *p + 165 * 8\n\t");
}

extern "C" DLL_EXPORT CryptSha1Final()
{
asm("jmp *p + 166 * 8\n\t");
}

extern "C" DLL_EXPORT CryptSha1Init()
{
asm("jmp *p + 167 * 8\n\t");
}

extern "C" DLL_EXPORT CryptSha1Init2()
{
asm("jmp *p + 168 * 8\n\t");
}

extern "C" DLL_EXPORT CryptSha1Update()
{
asm("jmp *p + 169 * 8\n\t");
}

extern "C" DLL_EXPORT CryptSha2Final()
{
asm("jmp *p + 170 * 8\n\t");
}

extern "C" DLL_EXPORT CryptSha2Init()
{
asm("jmp *p + 171 * 8\n\t");
}

extern "C" DLL_EXPORT CryptSha2Update()
{
asm("jmp *p + 172 * 8\n\t");
}

extern "C" DLL_EXPORT CryptStp1DecryptData()
{
asm("jmp *p + 173 * 8\n\t");
}

extern "C" DLL_EXPORT CryptStp1DecryptHash()
{
asm("jmp *p + 174 * 8\n\t");
}

extern "C" DLL_EXPORT CryptStp1DecryptSize()
{
asm("jmp *p + 175 * 8\n\t");
}

extern "C" DLL_EXPORT CryptStp1Enabled()
{
asm("jmp *p + 176 * 8\n\t");
}

extern "C" DLL_EXPORT CryptStp1EncryptData()
{
asm("jmp *p + 177 * 8\n\t");
}

extern "C" DLL_EXPORT CryptStp1EncryptHash()
{
asm("jmp *p + 178 * 8\n\t");
}

extern "C" DLL_EXPORT CryptStp1EncryptSize()
{
asm("jmp *p + 179 * 8\n\t");
}

extern "C" DLL_EXPORT CryptStp1MakeWallet()
{
asm("jmp *p + 180 * 8\n\t");
}

extern "C" DLL_EXPORT CryptStp1OpenWallet()
{
asm("jmp *p + 181 * 8\n\t");
}

extern "C" DLL_EXPORT CryptStp1SetShared()
{
asm("jmp *p + 182 * 8\n\t");
}

extern "C" DLL_EXPORT CryptStp1UseSecret()
{
asm("jmp *p + 183 * 8\n\t");
}

extern "C" DLL_EXPORT CryptStp1UseTicket()
{
asm("jmp *p + 184 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyAddrFromHostAddr()
{
asm("jmp *p + 185 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyAddrGetLocalAddr()
{
asm("jmp *p + 186 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyAddrToHostAddr()
{
asm("jmp *p + 187 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyCertCAPreloadCerts()
{
asm("jmp *p + 188 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyCertCARequestCert()
{
asm("jmp *p + 189 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyCertCARequestDone()
{
asm("jmp *p + 190 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyCertCARequestFree()
{
asm("jmp *p + 191 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyCertControl()
{
asm("jmp *p + 192 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyCertCreate()
{
asm("jmp *p + 193 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyCertDestroy()
{
asm("jmp *p + 194 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyCertStatus()
{
asm("jmp *p + 195 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyErrGetHResult()
{
asm("jmp *p + 196 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyGifDecodeImage()
{
asm("jmp *p + 197 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyGifDecodeImage32()
{
asm("jmp *p + 198 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyGifDecodePalette()
{
asm("jmp *p + 199 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyGifIdentify()
{
asm("jmp *p + 200 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyGifParse()
{
asm("jmp *p + 201 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyGraphCreate()
{
asm("jmp *p + 202 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyGraphDecodeHeader()
{
asm("jmp *p + 203 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyGraphDecodeImage()
{
asm("jmp *p + 204 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyGraphDestroy()
{
asm("jmp *p + 205 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyJpgCreate()
{
asm("jmp *p + 206 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyJpgDecodeHeader()
{
asm("jmp *p + 207 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyJpgDecodeImage()
{
asm("jmp *p + 208 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyJpgDestroy()
{
asm("jmp *p + 209 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyJpgIdentify()
{
asm("jmp *p + 210 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyJpgReset()
{
asm("jmp *p + 211 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyMemAlloc()
{
asm("jmp *p + 212 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyMemFree()
{
asm("jmp *p + 213 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyMemFuncSet()
{
asm("jmp *p + 214 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyMemGroupEnter()
{
asm("jmp *p + 215 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyMemGroupLeave()
{
asm("jmp *p + 216 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyMemGroupQuery()
{
asm("jmp *p + 217 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyNameCreateCanonical()
{
asm("jmp *p + 218 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyPngCreate()
{
asm("jmp *p + 219 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyPngDecodeImage()
{
asm("jmp *p + 220 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyPngDestroy()
{
asm("jmp *p + 221 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyPngIdentify()
{
asm("jmp *p + 222 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyPngParse()
{
asm("jmp *p + 223 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyUsernameCompare()
{
asm("jmp *p + 224 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyUsernameHash()
{
asm("jmp *p + 225 * 8\n\t");
}

extern "C" DLL_EXPORT DirtyUsernameSubstr()
{
asm("jmp *p + 226 * 8\n\t");
}

extern "C" DLL_EXPORT DispListAdd()
{
asm("jmp *p + 227 * 8\n\t");
}

extern "C" DLL_EXPORT DispListChange()
{
asm("jmp *p + 228 * 8\n\t");
}

extern "C" DLL_EXPORT DispListClear()
{
asm("jmp *p + 229 * 8\n\t");
}

extern "C" DLL_EXPORT DispListCount()
{
asm("jmp *p + 230 * 8\n\t");
}

extern "C" DLL_EXPORT DispListCreate()
{
asm("jmp *p + 231 * 8\n\t");
}

extern "C" DLL_EXPORT DispListDataGet()
{
asm("jmp *p + 232 * 8\n\t");
}

extern "C" DLL_EXPORT DispListDataSet()
{
asm("jmp *p + 233 * 8\n\t");
}

extern "C" DLL_EXPORT DispListDel()
{
asm("jmp *p + 234 * 8\n\t");
}

extern "C" DLL_EXPORT DispListDelByIndex()
{
asm("jmp *p + 235 * 8\n\t");
}

extern "C" DLL_EXPORT DispListDestroy()
{
asm("jmp *p + 236 * 8\n\t");
}

extern "C" DLL_EXPORT DispListDirty()
{
asm("jmp *p + 237 * 8\n\t");
}

extern "C" DLL_EXPORT DispListFilt()
{
asm("jmp *p + 238 * 8\n\t");
}

extern "C" DLL_EXPORT DispListGet()
{
asm("jmp *p + 239 * 8\n\t");
}

extern "C" DLL_EXPORT DispListIndex()
{
asm("jmp *p + 240 * 8\n\t");
}

extern "C" DLL_EXPORT DispListOrder()
{
asm("jmp *p + 241 * 8\n\t");
}

extern "C" DLL_EXPORT DispListSet()
{
asm("jmp *p + 242 * 8\n\t");
}

extern "C" DLL_EXPORT DispListShown()
{
asm("jmp *p + 243 * 8\n\t");
}

extern "C" DLL_EXPORT DispListSort()
{
asm("jmp *p + 244 * 8\n\t");
}

extern "C" DLL_EXPORT FriendApiAddCallback()
{
asm("jmp *p + 245 * 8\n\t");
}

extern "C" DLL_EXPORT FriendApiBlockUser()
{
asm("jmp *p + 246 * 8\n\t");
}

extern "C" DLL_EXPORT FriendApiControl()
{
asm("jmp *p + 247 * 8\n\t");
}

extern "C" DLL_EXPORT FriendApiCreate()
{
asm("jmp *p + 248 * 8\n\t");
}

extern "C" DLL_EXPORT FriendApiDestroy()
{
asm("jmp *p + 249 * 8\n\t");
}

extern "C" DLL_EXPORT FriendApiGetBlockList()
{
asm("jmp *p + 250 * 8\n\t");
}

extern "C" DLL_EXPORT FriendApiGetBlockListVersion()
{
asm("jmp *p + 251 * 8\n\t");
}

extern "C" DLL_EXPORT FriendApiGetFriendsList()
{
asm("jmp *p + 252 * 8\n\t");
}

extern "C" DLL_EXPORT FriendApiGetFriendsListVersion()
{
asm("jmp *p + 253 * 8\n\t");
}

extern "C" DLL_EXPORT FriendApiIsUserBlocked()
{
asm("jmp *p + 254 * 8\n\t");
}

extern "C" DLL_EXPORT FriendApiRemoveCallback()
{
asm("jmp *p + 255 * 8\n\t");
}

extern "C" DLL_EXPORT FriendApiStatus()
{
asm("jmp *p + 256 * 8\n\t");
}

extern "C" DLL_EXPORT FriendApiUnblockUser()
{
asm("jmp *p + 257 * 8\n\t");
}

extern "C" DLL_EXPORT FriendApiUpdate()
{
asm("jmp *p + 258 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiCancelOp()
{
asm("jmp *p + 259 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiConnect()
{
asm("jmp *p + 260 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiCreate()
{
asm("jmp *p + 261 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiCreate2()
{
asm("jmp *p + 262 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiDestroy()
{
asm("jmp *p + 263 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiDisconnect()
{
asm("jmp *p + 264 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiFindUsers()
{
asm("jmp *p + 265 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiGetConnectState()
{
asm("jmp *p + 266 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiGetEmailForwarding()
{
asm("jmp *p + 267 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiGetLastOpStatus()
{
asm("jmp *p + 268 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiGetMyTitleName()
{
asm("jmp *p + 269 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiGetTitleName()
{
asm("jmp *p + 270 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiGetUserIndex()
{
asm("jmp *p + 271 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiInitialize()
{
asm("jmp *p + 272 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiOverrideConstants()
{
asm("jmp *p + 273 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiOverrideMaxMessagesPerBuddy()
{
asm("jmp *p + 274 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiOverrideXblIsSameProductCheck()
{
asm("jmp *p + 275 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiPresenceDiff()
{
asm("jmp *p + 276 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiPresenceExtra()
{
asm("jmp *p + 277 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiPresenceJoinable()
{
asm("jmp *p + 278 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiPresenceOffline()
{
asm("jmp *p + 279 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiPresenceSame()
{
asm("jmp *p + 280 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiPresenceSend()
{
asm("jmp *p + 281 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiPresenceSendSetPresence()
{
asm("jmp *p + 282 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiPresenceVOIPSend()
{
asm("jmp *p + 283 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiRegisterBuddyChangeCallback()
{
asm("jmp *p + 284 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiRegisterBuddyPresenceCallback()
{
asm("jmp *p + 285 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiRegisterConnectCallback()
{
asm("jmp *p + 286 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiRegisterGameInviteCallback()
{
asm("jmp *p + 287 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiRegisterNewMsgCallback()
{
asm("jmp *p + 288 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiResume()
{
asm("jmp *p + 289 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiSetDebugFunction()
{
asm("jmp *p + 290 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiSetEmailForwarding()
{
asm("jmp *p + 291 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiSetUserIndex()
{
asm("jmp *p + 292 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiSetUtf8TransTbl()
{
asm("jmp *p + 293 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiSuspend()
{
asm("jmp *p + 294 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiUpdate()
{
asm("jmp *p + 295 * 8\n\t");
}

extern "C" DLL_EXPORT HLBApiUserFound()
{
asm("jmp *p + 296 * 8\n\t");
}

extern "C" DLL_EXPORT HLBBudCanVoiceChat()
{
asm("jmp *p + 297 * 8\n\t");
}

extern "C" DLL_EXPORT HLBBudGetGameInviteFlags()
{
asm("jmp *p + 298 * 8\n\t");
}

extern "C" DLL_EXPORT HLBBudGetName()
{
asm("jmp *p + 299 * 8\n\t");
}

extern "C" DLL_EXPORT HLBBudGetPresence()
{
asm("jmp *p + 300 * 8\n\t");
}

extern "C" DLL_EXPORT HLBBudGetPresenceExtra()
{
asm("jmp *p + 301 * 8\n\t");
}

extern "C" DLL_EXPORT HLBBudGetState()
{
asm("jmp *p + 302 * 8\n\t");
}

extern "C" DLL_EXPORT HLBBudGetTitle()
{
asm("jmp *p + 303 * 8\n\t");
}

extern "C" DLL_EXPORT HLBBudGetVOIPState()
{
asm("jmp *p + 304 * 8\n\t");
}

extern "C" DLL_EXPORT HLBBudIsAvailableForChat()
{
asm("jmp *p + 305 * 8\n\t");
}

extern "C" DLL_EXPORT HLBBudIsBlocked()
{
asm("jmp *p + 306 * 8\n\t");
}

extern "C" DLL_EXPORT HLBBudIsIWannaBeHisBuddy()
{
asm("jmp *p + 307 * 8\n\t");
}

extern "C" DLL_EXPORT HLBBudIsInGroup()
{
asm("jmp *p + 308 * 8\n\t");
}

extern "C" DLL_EXPORT HLBBudIsJoinable()
{
asm("jmp *p + 309 * 8\n\t");
}

extern "C" DLL_EXPORT HLBBudIsNoReplyBud()
{
asm("jmp *p + 310 * 8\n\t");
}

extern "C" DLL_EXPORT HLBBudIsPassive()
{
asm("jmp *p + 311 * 8\n\t");
}

extern "C" DLL_EXPORT HLBBudIsRealBuddy()
{
asm("jmp *p + 312 * 8\n\t");
}

extern "C" DLL_EXPORT HLBBudIsSameProduct()
{
asm("jmp *p + 313 * 8\n\t");
}

extern "C" DLL_EXPORT HLBBudIsTemporary()
{
asm("jmp *p + 314 * 8\n\t");
}

extern "C" DLL_EXPORT HLBBudIsWannaBeMyBuddy()
{
asm("jmp *p + 315 * 8\n\t");
}

extern "C" DLL_EXPORT HLBBudJoinGame()
{
asm("jmp *p + 316 * 8\n\t");
}

extern "C" DLL_EXPORT HLBBudTempBuddyIs()
{
asm("jmp *p + 317 * 8\n\t");
}

extern "C" DLL_EXPORT HLBListAddToGroup()
{
asm("jmp *p + 318 * 8\n\t");
}

extern "C" DLL_EXPORT HLBListAnswerGameInvite()
{
asm("jmp *p + 319 * 8\n\t");
}

extern "C" DLL_EXPORT HLBListAnswerInvite()
{
asm("jmp *p + 320 * 8\n\t");
}

extern "C" DLL_EXPORT HLBListBlockBuddy()
{
asm("jmp *p + 321 * 8\n\t");
}

extern "C" DLL_EXPORT HLBListBuddyWithMsg()
{
asm("jmp *p + 322 * 8\n\t");
}

extern "C" DLL_EXPORT HLBListCancelAllInvites()
{
asm("jmp *p + 323 * 8\n\t");
}

extern "C" DLL_EXPORT HLBListCancelGameInvite()
{
asm("jmp *p + 324 * 8\n\t");
}

extern "C" DLL_EXPORT HLBListChanged()
{
asm("jmp *p + 325 * 8\n\t");
}

extern "C" DLL_EXPORT HLBListClearGroup()
{
asm("jmp *p + 326 * 8\n\t");
}

extern "C" DLL_EXPORT HLBListDeleteTempBuddy()
{
asm("jmp *p + 327 * 8\n\t");
}

extern "C" DLL_EXPORT HLBListDisableSorting()
{
asm("jmp *p + 328 * 8\n\t");
}

extern "C" DLL_EXPORT HLBListFlagTempBuddy()
{
asm("jmp *p + 329 * 8\n\t");
}

extern "C" DLL_EXPORT HLBListGameInviteBuddy()
{
asm("jmp *p + 330 * 8\n\t");
}

extern "C" DLL_EXPORT HLBListGetBuddyByIndex()
{
asm("jmp *p + 331 * 8\n\t");
}

extern "C" DLL_EXPORT HLBListGetBuddyByName()
{
asm("jmp *p + 332 * 8\n\t");
}

extern "C" DLL_EXPORT HLBListGetBuddyCount()
{
asm("jmp *p + 333 * 8\n\t");
}

extern "C" DLL_EXPORT HLBListGetBuddyCountByFlags()
{
asm("jmp *p + 334 * 8\n\t");
}

extern "C" DLL_EXPORT HLBListGetGameSessionID()
{
asm("jmp *p + 335 * 8\n\t");
}

extern "C" DLL_EXPORT HLBListGetIndexByName()
{
asm("jmp *p + 336 * 8\n\t");
}

extern "C" DLL_EXPORT HLBListInviteBuddy()
{
asm("jmp *p + 337 * 8\n\t");
}

extern "C" DLL_EXPORT HLBListRemoveFromGroup()
{
asm("jmp *p + 338 * 8\n\t");
}

extern "C" DLL_EXPORT HLBListSendChatMsg()
{
asm("jmp *p + 339 * 8\n\t");
}

extern "C" DLL_EXPORT HLBListSendMsgToGroup()
{
asm("jmp *p + 340 * 8\n\t");
}

extern "C" DLL_EXPORT HLBListSetGameInviteSessionID()
{
asm("jmp *p + 341 * 8\n\t");
}

extern "C" DLL_EXPORT HLBListSetSortFunction()
{
asm("jmp *p + 342 * 8\n\t");
}

extern "C" DLL_EXPORT HLBListUnBlockBuddy()
{
asm("jmp *p + 343 * 8\n\t");
}

extern "C" DLL_EXPORT HLBListUnFlagTempBuddy()
{
asm("jmp *p + 344 * 8\n\t");
}

extern "C" DLL_EXPORT HLBListUnMakeBuddy()
{
asm("jmp *p + 345 * 8\n\t");
}

extern "C" DLL_EXPORT HLBMsgListDelete()
{
asm("jmp *p + 346 * 8\n\t");
}

extern "C" DLL_EXPORT HLBMsgListDeleteAll()
{
asm("jmp *p + 347 * 8\n\t");
}

extern "C" DLL_EXPORT HLBMsgListGetFirstUnreadMsg()
{
asm("jmp *p + 348 * 8\n\t");
}

extern "C" DLL_EXPORT HLBMsgListGetMsgByIndex()
{
asm("jmp *p + 349 * 8\n\t");
}

extern "C" DLL_EXPORT HLBMsgListGetMsgText()
{
asm("jmp *p + 350 * 8\n\t");
}

extern "C" DLL_EXPORT HLBMsgListGetTotalCount()
{
asm("jmp *p + 351 * 8\n\t");
}

extern "C" DLL_EXPORT HLBMsgListGetUnreadCount()
{
asm("jmp *p + 352 * 8\n\t");
}

extern "C" DLL_EXPORT HLBMsgListMsgInject()
{
asm("jmp *p + 353 * 8\n\t");
}

extern "C" DLL_EXPORT HashNumAdd()
{
asm("jmp *p + 354 * 8\n\t");
}

extern "C" DLL_EXPORT HashNumDel()
{
asm("jmp *p + 355 * 8\n\t");
}

extern "C" DLL_EXPORT HashNumFind()
{
asm("jmp *p + 356 * 8\n\t");
}

extern "C" DLL_EXPORT HashNumReplace()
{
asm("jmp *p + 357 * 8\n\t");
}

extern "C" DLL_EXPORT HashStrAdd()
{
asm("jmp *p + 358 * 8\n\t");
}

extern "C" DLL_EXPORT HashStrDel()
{
asm("jmp *p + 359 * 8\n\t");
}

extern "C" DLL_EXPORT HashStrFind()
{
asm("jmp *p + 360 * 8\n\t");
}

extern "C" DLL_EXPORT HashStrReplace()
{
asm("jmp *p + 361 * 8\n\t");
}

extern "C" DLL_EXPORT HasherClear()
{
asm("jmp *p + 362 * 8\n\t");
}

extern "C" DLL_EXPORT HasherCount()
{
asm("jmp *p + 363 * 8\n\t");
}

extern "C" DLL_EXPORT HasherCreate()
{
asm("jmp *p + 364 * 8\n\t");
}

extern "C" DLL_EXPORT HasherDestroy()
{
asm("jmp *p + 365 * 8\n\t");
}

extern "C" DLL_EXPORT HasherEnum()
{
asm("jmp *p + 366 * 8\n\t");
}

extern "C" DLL_EXPORT HasherEnumInit()
{
asm("jmp *p + 367 * 8\n\t");
}

extern "C" DLL_EXPORT HasherExpand()
{
asm("jmp *p + 368 * 8\n\t");
}

extern "C" DLL_EXPORT HasherFlush()
{
asm("jmp *p + 369 * 8\n\t");
}

extern "C" DLL_EXPORT HasherSetStrCompareFunc()
{
asm("jmp *p + 370 * 8\n\t");
}

extern "C" DLL_EXPORT HttpManagerAlloc()
{
asm("jmp *p + 371 * 8\n\t");
}

extern "C" DLL_EXPORT HttpManagerCallback()
{
asm("jmp *p + 372 * 8\n\t");
}

extern "C" DLL_EXPORT HttpManagerControl()
{
asm("jmp *p + 373 * 8\n\t");
}

extern "C" DLL_EXPORT HttpManagerCreate()
{
asm("jmp *p + 374 * 8\n\t");
}

extern "C" DLL_EXPORT HttpManagerDestroy()
{
asm("jmp *p + 375 * 8\n\t");
}

extern "C" DLL_EXPORT HttpManagerFree()
{
asm("jmp *p + 376 * 8\n\t");
}

extern "C" DLL_EXPORT HttpManagerGet()
{
asm("jmp *p + 377 * 8\n\t");
}

extern "C" DLL_EXPORT HttpManagerPost()
{
asm("jmp *p + 378 * 8\n\t");
}

extern "C" DLL_EXPORT HttpManagerRecv()
{
asm("jmp *p + 379 * 8\n\t");
}

extern "C" DLL_EXPORT HttpManagerRecvAll()
{
asm("jmp *p + 380 * 8\n\t");
}

extern "C" DLL_EXPORT HttpManagerRequestCb()
{
asm("jmp *p + 381 * 8\n\t");
}

extern "C" DLL_EXPORT HttpManagerSend()
{
asm("jmp *p + 382 * 8\n\t");
}

extern "C" DLL_EXPORT HttpManagerSetBaseUrl()
{
asm("jmp *p + 383 * 8\n\t");
}

extern "C" DLL_EXPORT HttpManagerStatus()
{
asm("jmp *p + 384 * 8\n\t");
}

extern "C" DLL_EXPORT HttpManagerUpdate()
{
asm("jmp *p + 385 * 8\n\t");
}

extern "C" DLL_EXPORT JsonAddDate()
{
asm("jmp *p + 386 * 8\n\t");
}

extern "C" DLL_EXPORT JsonAddInt()
{
asm("jmp *p + 387 * 8\n\t");
}

extern "C" DLL_EXPORT JsonAddNum()
{
asm("jmp *p + 388 * 8\n\t");
}

extern "C" DLL_EXPORT JsonAddStr()
{
asm("jmp *p + 389 * 8\n\t");
}

extern "C" DLL_EXPORT JsonArrayEnd()
{
asm("jmp *p + 390 * 8\n\t");
}

extern "C" DLL_EXPORT JsonArrayStart()
{
asm("jmp *p + 391 * 8\n\t");
}

extern "C" DLL_EXPORT JsonBufSizeIncrease()
{
asm("jmp *p + 392 * 8\n\t");
}

extern "C" DLL_EXPORT JsonFind()
{
asm("jmp *p + 393 * 8\n\t");
}

extern "C" DLL_EXPORT JsonFind2()
{
asm("jmp *p + 394 * 8\n\t");
}

extern "C" DLL_EXPORT JsonFinish()
{
asm("jmp *p + 395 * 8\n\t");
}

extern "C" DLL_EXPORT JsonFormatPrintf()
{
asm("jmp *p + 396 * 8\n\t");
}

extern "C" DLL_EXPORT JsonFormatVPrintf()
{
asm("jmp *p + 397 * 8\n\t");
}

extern "C" DLL_EXPORT JsonGetBoolean()
{
asm("jmp *p + 398 * 8\n\t");
}

extern "C" DLL_EXPORT JsonGetDate()
{
asm("jmp *p + 399 * 8\n\t");
}

extern "C" DLL_EXPORT JsonGetEnum()
{
asm("jmp *p + 400 * 8\n\t");
}

extern "C" DLL_EXPORT JsonGetInteger()
{
asm("jmp *p + 401 * 8\n\t");
}

extern "C" DLL_EXPORT JsonGetListItemEnd()
{
asm("jmp *p + 402 * 8\n\t");
}

extern "C" DLL_EXPORT JsonGetNumber()
{
asm("jmp *p + 403 * 8\n\t");
}

extern "C" DLL_EXPORT JsonGetString()
{
asm("jmp *p + 404 * 8\n\t");
}

extern "C" DLL_EXPORT JsonInit()
{
asm("jmp *p + 405 * 8\n\t");
}

extern "C" DLL_EXPORT JsonObjectEnd()
{
asm("jmp *p + 406 * 8\n\t");
}

extern "C" DLL_EXPORT JsonObjectStart()
{
asm("jmp *p + 407 * 8\n\t");
}

extern "C" DLL_EXPORT JsonParse()
{
asm("jmp *p + 408 * 8\n\t");
}

extern "C" DLL_EXPORT JsonSeekValue()
{
asm("jmp *p + 409 * 8\n\t");
}

extern "C" DLL_EXPORT LobbyLanControl()
{
asm("jmp *p + 410 * 8\n\t");
}

extern "C" DLL_EXPORT LobbyLanCreate2()
{
asm("jmp *p + 411 * 8\n\t");
}

extern "C" DLL_EXPORT LobbyLanCreateGame()
{
asm("jmp *p + 412 * 8\n\t");
}

extern "C" DLL_EXPORT LobbyLanDestroy()
{
asm("jmp *p + 413 * 8\n\t");
}

extern "C" DLL_EXPORT LobbyLanGetGameInfo()
{
asm("jmp *p + 414 * 8\n\t");
}

extern "C" DLL_EXPORT LobbyLanGetGameList()
{
asm("jmp *p + 415 * 8\n\t");
}

extern "C" DLL_EXPORT LobbyLanGetPlyrList()
{
asm("jmp *p + 416 * 8\n\t");
}

extern "C" DLL_EXPORT LobbyLanJoinGame()
{
asm("jmp *p + 417 * 8\n\t");
}

extern "C" DLL_EXPORT LobbyLanJoinGameByIndex()
{
asm("jmp *p + 418 * 8\n\t");
}

extern "C" DLL_EXPORT LobbyLanLeaveGame()
{
asm("jmp *p + 419 * 8\n\t");
}

extern "C" DLL_EXPORT LobbyLanRecvfrom()
{
asm("jmp *p + 420 * 8\n\t");
}

extern "C" DLL_EXPORT LobbyLanReset()
{
asm("jmp *p + 421 * 8\n\t");
}

extern "C" DLL_EXPORT LobbyLanSendto()
{
asm("jmp *p + 422 * 8\n\t");
}

extern "C" DLL_EXPORT LobbyLanSetCallback()
{
asm("jmp *p + 423 * 8\n\t");
}

extern "C" DLL_EXPORT LobbyLanSetNote()
{
asm("jmp *p + 424 * 8\n\t");
}

extern "C" DLL_EXPORT LobbyLanSetPlyrNote()
{
asm("jmp *p + 425 * 8\n\t");
}

extern "C" DLL_EXPORT LobbyLanStartGame()
{
asm("jmp *p + 426 * 8\n\t");
}

extern "C" DLL_EXPORT LobbyLanStatus()
{
asm("jmp *p + 427 * 8\n\t");
}

extern "C" DLL_EXPORT LobbyMSort()
{
asm("jmp *p + 428 * 8\n\t");
}

extern "C" DLL_EXPORT MurmurHash3()
{
asm("jmp *p + 429 * 8\n\t");
}

extern "C" DLL_EXPORT MurmurHash3Final()
{
asm("jmp *p + 430 * 8\n\t");
}

extern "C" DLL_EXPORT MurmurHash3Init()
{
asm("jmp *p + 431 * 8\n\t");
}

extern "C" DLL_EXPORT MurmurHash3Init2()
{
asm("jmp *p + 432 * 8\n\t");
}

extern "C" DLL_EXPORT MurmurHash3Update()
{
asm("jmp *p + 433 * 8\n\t");
}

extern "C" DLL_EXPORT NetConnConnect()
{
asm("jmp *p + 434 * 8\n\t");
}

extern "C" DLL_EXPORT NetConnControl()
{
asm("jmp *p + 435 * 8\n\t");
}

extern "C" DLL_EXPORT NetConnCopyParam()
{
asm("jmp *p + 436 * 8\n\t");
}

extern "C" DLL_EXPORT NetConnDirtyCertCreate()
{
asm("jmp *p + 437 * 8\n\t");
}

extern "C" DLL_EXPORT NetConnDisconnect()
{
asm("jmp *p + 438 * 8\n\t");
}

extern "C" DLL_EXPORT NetConnElapsed()
{
asm("jmp *p + 439 * 8\n\t");
}

extern "C" DLL_EXPORT NetConnGetEnvStr()
{
asm("jmp *p + 440 * 8\n\t");
}

extern "C" DLL_EXPORT NetConnIdle()
{
asm("jmp *p + 441 * 8\n\t");
}

extern "C" DLL_EXPORT NetConnIdleAdd()
{
asm("jmp *p + 442 * 8\n\t");
}

extern "C" DLL_EXPORT NetConnIdleDel()
{
asm("jmp *p + 443 * 8\n\t");
}

extern "C" DLL_EXPORT NetConnIdleShutdown()
{
asm("jmp *p + 444 * 8\n\t");
}

extern "C" DLL_EXPORT NetConnMAC()
{
asm("jmp *p + 445 * 8\n\t");
}

extern "C" DLL_EXPORT NetConnMachineId()
{
asm("jmp *p + 446 * 8\n\t");
}

extern "C" DLL_EXPORT NetConnQuery()
{
asm("jmp *p + 447 * 8\n\t");
}

extern "C" DLL_EXPORT NetConnSetMachineId()
{
asm("jmp *p + 448 * 8\n\t");
}

extern "C" DLL_EXPORT NetConnShutdown()
{
asm("jmp *p + 449 * 8\n\t");
}

extern "C" DLL_EXPORT NetConnSleep()
{
asm("jmp *p + 450 * 8\n\t");
}

extern "C" DLL_EXPORT NetConnStartup()
{
asm("jmp *p + 451 * 8\n\t");
}

extern "C" DLL_EXPORT NetConnStatus()
{
asm("jmp *p + 452 * 8\n\t");
}

extern "C" DLL_EXPORT NetConnTiming()
{
asm("jmp *p + 453 * 8\n\t");
}

extern "C" DLL_EXPORT NetCritEnter()
{
asm("jmp *p + 454 * 8\n\t");
}

extern "C" DLL_EXPORT NetCritInit()
{
asm("jmp *p + 455 * 8\n\t");
}

extern "C" DLL_EXPORT NetCritKill()
{
asm("jmp *p + 456 * 8\n\t");
}

extern "C" DLL_EXPORT NetCritLeave()
{
asm("jmp *p + 457 * 8\n\t");
}

extern "C" DLL_EXPORT NetCritTry()
{
asm("jmp *p + 458 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameDistControl()
{
asm("jmp *p + 459 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameDistCreate()
{
asm("jmp *p + 460 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameDistDestroy()
{
asm("jmp *p + 461 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameDistGetError()
{
asm("jmp *p + 462 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameDistGetErrorText()
{
asm("jmp *p + 463 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameDistInputCheck()
{
asm("jmp *p + 464 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameDistInputClear()
{
asm("jmp *p + 465 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameDistInputLocal()
{
asm("jmp *p + 466 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameDistInputLocalMulti()
{
asm("jmp *p + 467 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameDistInputPeek()
{
asm("jmp *p + 468 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameDistInputQuery()
{
asm("jmp *p + 469 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameDistInputQueryMulti()
{
asm("jmp *p + 470 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameDistInputRate()
{
asm("jmp *p + 471 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameDistMetaSetup()
{
asm("jmp *p + 472 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameDistMultiSetup()
{
asm("jmp *p + 473 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameDistResetError()
{
asm("jmp *p + 474 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameDistSendStats()
{
asm("jmp *p + 475 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameDistServAddClient()
{
asm("jmp *p + 476 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameDistServControl()
{
asm("jmp *p + 477 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameDistServCreate()
{
asm("jmp *p + 478 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameDistServDelClient()
{
asm("jmp *p + 479 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameDistServDestroy()
{
asm("jmp *p + 480 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameDistServDiscClient()
{
asm("jmp *p + 481 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameDistServExplainError()
{
asm("jmp *p + 482 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameDistServHighWaterChanged()
{
asm("jmp *p + 483 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameDistServStartGame()
{
asm("jmp *p + 484 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameDistServStatus()
{
asm("jmp *p + 485 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameDistServStopGame()
{
asm("jmp *p + 486 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameDistServUpdate()
{
asm("jmp *p + 487 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameDistServUpdateClient()
{
asm("jmp *p + 488 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameDistSetProc()
{
asm("jmp *p + 489 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameDistSetServer()
{
asm("jmp *p + 490 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameDistStatus()
{
asm("jmp *p + 491 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameDistUpdate()
{
asm("jmp *p + 492 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameLinkCallback()
{
asm("jmp *p + 493 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameLinkControl()
{
asm("jmp *p + 494 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameLinkCreate()
{
asm("jmp *p + 495 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameLinkCreateStream()
{
asm("jmp *p + 496 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameLinkDestroy()
{
asm("jmp *p + 497 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameLinkDestroyStream()
{
asm("jmp *p + 498 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameLinkPeek()
{
asm("jmp *p + 499 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameLinkPeek2()
{
asm("jmp *p + 500 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameLinkRecv()
{
asm("jmp *p + 501 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameLinkRecv2()
{
asm("jmp *p + 502 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameLinkSend()
{
asm("jmp *p + 503 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameLinkStatus()
{
asm("jmp *p + 504 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameLinkUpdate()
{
asm("jmp *p + 505 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameUtilAdvert()
{
asm("jmp *p + 506 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameUtilComplete()
{
asm("jmp *p + 507 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameUtilConnect()
{
asm("jmp *p + 508 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameUtilControl()
{
asm("jmp *p + 509 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameUtilCreate()
{
asm("jmp *p + 510 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameUtilDestroy()
{
asm("jmp *p + 511 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameUtilLocate()
{
asm("jmp *p + 512 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameUtilQuery()
{
asm("jmp *p + 513 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameUtilReset()
{
asm("jmp *p + 514 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameUtilStatus()
{
asm("jmp *p + 515 * 8\n\t");
}

extern "C" DLL_EXPORT NetGameUtilWithdraw()
{
asm("jmp *p + 516 * 8\n\t");
}

extern "C" DLL_EXPORT NetHash()
{
asm("jmp *p + 517 * 8\n\t");
}

extern "C" DLL_EXPORT NetHashBin()
{
asm("jmp *p + 518 * 8\n\t");
}

extern "C" DLL_EXPORT NetIdleAdd()
{
asm("jmp *p + 519 * 8\n\t");
}

extern "C" DLL_EXPORT NetIdleCall()
{
asm("jmp *p + 520 * 8\n\t");
}

extern "C" DLL_EXPORT NetIdleDel()
{
asm("jmp *p + 521 * 8\n\t");
}

extern "C" DLL_EXPORT NetIdleDone()
{
asm("jmp *p + 522 * 8\n\t");
}

extern "C" DLL_EXPORT NetIdleReset()
{
asm("jmp *p + 523 * 8\n\t");
}

extern "C" DLL_EXPORT NetLibCreate()
{
asm("jmp *p + 524 * 8\n\t");
}

extern "C" DLL_EXPORT NetLibDestroy()
{
asm("jmp *p + 525 * 8\n\t");
}

extern "C" DLL_EXPORT NetRand()
{
asm("jmp *p + 526 * 8\n\t");
}

extern "C" DLL_EXPORT NetResourceCache()
{
asm("jmp *p + 527 * 8\n\t");
}

extern "C" DLL_EXPORT NetResourceCacheCheck()
{
asm("jmp *p + 528 * 8\n\t");
}

extern "C" DLL_EXPORT NetResourceCancel()
{
asm("jmp *p + 529 * 8\n\t");
}

extern "C" DLL_EXPORT NetResourceCreate()
{
asm("jmp *p + 530 * 8\n\t");
}

extern "C" DLL_EXPORT NetResourceDestroy()
{
asm("jmp *p + 531 * 8\n\t");
}

extern "C" DLL_EXPORT NetResourceFetch()
{
asm("jmp *p + 532 * 8\n\t");
}

extern "C" DLL_EXPORT NetResourceFetchString()
{
asm("jmp *p + 533 * 8\n\t");
}

extern "C" DLL_EXPORT NetTick()
{
asm("jmp *p + 534 * 8\n\t");
}

extern "C" DLL_EXPORT PingManagerCancelRequest()
{
asm("jmp *p + 535 * 8\n\t");
}

extern "C" DLL_EXPORT PingManagerCancelServerRequest()
{
asm("jmp *p + 536 * 8\n\t");
}

extern "C" DLL_EXPORT PingManagerCreate()
{
asm("jmp *p + 537 * 8\n\t");
}

extern "C" DLL_EXPORT PingManagerDestroy()
{
asm("jmp *p + 538 * 8\n\t");
}

extern "C" DLL_EXPORT PingManagerInvalidateAddress()
{
asm("jmp *p + 539 * 8\n\t");
}

extern "C" DLL_EXPORT PingManagerInvalidateCache()
{
asm("jmp *p + 540 * 8\n\t");
}

extern "C" DLL_EXPORT PingManagerPingAddress()
{
asm("jmp *p + 541 * 8\n\t");
}

extern "C" DLL_EXPORT PingManagerPingServer()
{
asm("jmp *p + 542 * 8\n\t");
}

extern "C" DLL_EXPORT PingManagerPingServer2()
{
asm("jmp *p + 543 * 8\n\t");
}

extern "C" DLL_EXPORT PingManagerUpdate()
{
asm("jmp *p + 544 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoAdvtAnnounce()
{
asm("jmp *p + 545 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoAdvtCancel()
{
asm("jmp *p + 546 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoAdvtConstruct()
{
asm("jmp *p + 547 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoAdvtDestroy()
{
asm("jmp *p + 548 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoAdvtLocate()
{
asm("jmp *p + 549 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoAdvtQuery()
{
asm("jmp *p + 550 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoAriesConnect()
{
asm("jmp *p + 551 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoAriesCreate()
{
asm("jmp *p + 552 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoAriesDestroy()
{
asm("jmp *p + 553 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoAriesListen()
{
asm("jmp *p + 554 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoAriesPeek()
{
asm("jmp *p + 555 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoAriesRecv()
{
asm("jmp *p + 556 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoAriesSecure()
{
asm("jmp *p + 557 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoAriesSend()
{
asm("jmp *p + 558 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoAriesSetKey()
{
asm("jmp *p + 559 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoAriesStatus()
{
asm("jmp *p + 560 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoAriesTick()
{
asm("jmp *p + 561 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoAriesUnconnect()
{
asm("jmp *p + 562 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoAriesUnlisten()
{
asm("jmp *p + 563 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoAriesUpdate()
{
asm("jmp *p + 564 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpAbort()
{
asm("jmp *p + 565 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpCallback()
{
asm("jmp *p + 566 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpCheckKeepAlive()
{
asm("jmp *p + 567 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpClrCACerts()
{
asm("jmp *p + 568 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpControl()
{
asm("jmp *p + 569 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpCreate()
{
asm("jmp *p + 570 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpDelete()
{
asm("jmp *p + 571 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpDestroy()
{
asm("jmp *p + 572 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpExtractHeaderValue()
{
asm("jmp *p + 573 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpFindHeaderValue()
{
asm("jmp *p + 574 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpGet()
{
asm("jmp *p + 575 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpGetHeaderValue()
{
asm("jmp *p + 576 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpGetLocationHeader()
{
asm("jmp *p + 577 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpGetNextHeader()
{
asm("jmp *p + 578 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpOptions()
{
asm("jmp *p + 579 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpParseHeaderCode()
{
asm("jmp *p + 580 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpPost()
{
asm("jmp *p + 581 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpRecv()
{
asm("jmp *p + 582 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpRecvAll()
{
asm("jmp *p + 583 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpRequestCb()
{
asm("jmp *p + 584 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpSend()
{
asm("jmp *p + 585 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpServCallback()
{
asm("jmp *p + 586 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpServControl()
{
asm("jmp *p + 587 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpServCreate()
{
asm("jmp *p + 588 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpServDestroy()
{
asm("jmp *p + 589 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpServStatus()
{
asm("jmp *p + 590 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpServUpdate()
{
asm("jmp *p + 591 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpSetBaseUrl()
{
asm("jmp *p + 592 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpSetCACert()
{
asm("jmp *p + 593 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpSetCACert2()
{
asm("jmp *p + 594 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpStatus()
{
asm("jmp *p + 595 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpUpdate()
{
asm("jmp *p + 596 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpUrlEncodeIntParm()
{
asm("jmp *p + 597 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpUrlEncodeStrParm()
{
asm("jmp *p + 598 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpUrlEncodeStrParm2()
{
asm("jmp *p + 599 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpUrlParse()
{
asm("jmp *p + 600 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpUrlParse2()
{
asm("jmp *p + 601 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoHttpValidateAllCA()
{
asm("jmp *p + 602 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoMangleComplete()
{
asm("jmp *p + 603 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoMangleConnect()
{
asm("jmp *p + 604 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoMangleConnect2()
{
asm("jmp *p + 605 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoMangleConnectSocket()
{
asm("jmp *p + 606 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoMangleControl()
{
asm("jmp *p + 607 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoMangleCreate()
{
asm("jmp *p + 608 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoMangleDestroy()
{
asm("jmp *p + 609 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoMangleReport()
{
asm("jmp *p + 610 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoMangleStatus()
{
asm("jmp *p + 611 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoMangleUpdate()
{
asm("jmp *p + 612 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoNameAsync()
{
asm("jmp *p + 613 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoNameSync()
{
asm("jmp *p + 614 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoPingControl()
{
asm("jmp *p + 615 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoPingCreate()
{
asm("jmp *p + 616 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoPingDestroy()
{
asm("jmp *p + 617 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoPingRequest()
{
asm("jmp *p + 618 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoPingRequestServer()
{
asm("jmp *p + 619 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoPingResponse()
{
asm("jmp *p + 620 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoSSLAccept()
{
asm("jmp *p + 621 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoSSLBind()
{
asm("jmp *p + 622 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoSSLClrCACerts()
{
asm("jmp *p + 623 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoSSLConnect()
{
asm("jmp *p + 624 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoSSLControl()
{
asm("jmp *p + 625 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoSSLCreate()
{
asm("jmp *p + 626 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoSSLDestroy()
{
asm("jmp *p + 627 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoSSLDisconnect()
{
asm("jmp *p + 628 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoSSLListen()
{
asm("jmp *p + 629 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoSSLRecv()
{
asm("jmp *p + 630 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoSSLReset()
{
asm("jmp *p + 631 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoSSLSend()
{
asm("jmp *p + 632 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoSSLSetCACert()
{
asm("jmp *p + 633 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoSSLSetCACert2()
{
asm("jmp *p + 634 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoSSLShutdown()
{
asm("jmp *p + 635 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoSSLStartup()
{
asm("jmp *p + 636 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoSSLStat()
{
asm("jmp *p + 637 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoSSLUpdate()
{
asm("jmp *p + 638 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoSSLValidateAllCA()
{
asm("jmp *p + 639 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoStreamClose()
{
asm("jmp *p + 640 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoStreamControl()
{
asm("jmp *p + 641 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoStreamCreate()
{
asm("jmp *p + 642 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoStreamDestroy()
{
asm("jmp *p + 643 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoStreamOpen()
{
asm("jmp *p + 644 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoStreamPause()
{
asm("jmp *p + 645 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoStreamRead()
{
asm("jmp *p + 646 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoStreamSetCallback()
{
asm("jmp *p + 647 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoStreamSetHttpCallback()
{
asm("jmp *p + 648 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoStreamStatus()
{
asm("jmp *p + 649 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoStreamUpdate()
{
asm("jmp *p + 650 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoTunnelAlloc()
{
asm("jmp *p + 651 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoTunnelCallback()
{
asm("jmp *p + 652 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoTunnelControl()
{
asm("jmp *p + 653 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoTunnelCreate()
{
asm("jmp *p + 654 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoTunnelDestroy()
{
asm("jmp *p + 655 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoTunnelFree()
{
asm("jmp *p + 656 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoTunnelFree2()
{
asm("jmp *p + 657 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoTunnelRawSendto()
{
asm("jmp *p + 658 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoTunnelStatus()
{
asm("jmp *p + 659 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoTunnelUpdate()
{
asm("jmp *p + 660 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoTunnelUpdatePortList()
{
asm("jmp *p + 661 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoUdpBind()
{
asm("jmp *p + 662 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoUdpConnect()
{
asm("jmp *p + 663 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoUdpCreate()
{
asm("jmp *p + 664 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoUdpDestroy()
{
asm("jmp *p + 665 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoUdpDisconnect()
{
asm("jmp *p + 666 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoUdpGetLocalAddr()
{
asm("jmp *p + 667 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoUdpRecvFrom()
{
asm("jmp *p + 668 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoUdpSend()
{
asm("jmp *p + 669 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoUdpSendTo()
{
asm("jmp *p + 670 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoUdpUpdate()
{
asm("jmp *p + 671 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoUpnpControl()
{
asm("jmp *p + 672 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoUpnpCreate()
{
asm("jmp *p + 673 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoUpnpDestroy()
{
asm("jmp *p + 674 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoUpnpGetRef()
{
asm("jmp *p + 675 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoUpnpStatus()
{
asm("jmp *p + 676 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoUpnpUpdate()
{
asm("jmp *p + 677 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoWebSocketAccept()
{
asm("jmp *p + 678 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoWebSocketConnect()
{
asm("jmp *p + 679 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoWebSocketConnect2()
{
asm("jmp *p + 680 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoWebSocketControl()
{
asm("jmp *p + 681 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoWebSocketCreate()
{
asm("jmp *p + 682 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoWebSocketCreate2()
{
asm("jmp *p + 683 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoWebSocketDestroy()
{
asm("jmp *p + 684 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoWebSocketDisconnect()
{
asm("jmp *p + 685 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoWebSocketListen()
{
asm("jmp *p + 686 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoWebSocketRecv()
{
asm("jmp *p + 687 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoWebSocketSend()
{
asm("jmp *p + 688 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoWebSocketStatus()
{
asm("jmp *p + 689 * 8\n\t");
}

extern "C" DLL_EXPORT ProtoWebSocketUpdate()
{
asm("jmp *p + 690 * 8\n\t");
}

extern "C" DLL_EXPORT QosApiCancelRequest()
{
asm("jmp *p + 691 * 8\n\t");
}

extern "C" DLL_EXPORT QosApiControl()
{
asm("jmp *p + 692 * 8\n\t");
}

extern "C" DLL_EXPORT QosApiCreate()
{
asm("jmp *p + 693 * 8\n\t");
}

extern "C" DLL_EXPORT QosApiDestroy()
{
asm("jmp *p + 694 * 8\n\t");
}

extern "C" DLL_EXPORT QosApiGetNatType()
{
asm("jmp *p + 695 * 8\n\t");
}

extern "C" DLL_EXPORT QosApiListen()
{
asm("jmp *p + 696 * 8\n\t");
}

extern "C" DLL_EXPORT QosApiRequest()
{
asm("jmp *p + 697 * 8\n\t");
}

extern "C" DLL_EXPORT QosApiServiceRequest()
{
asm("jmp *p + 698 * 8\n\t");
}

extern "C" DLL_EXPORT QosApiStatus()
{
asm("jmp *p + 699 * 8\n\t");
}

extern "C" DLL_EXPORT SockaddrCompare()
{
asm("jmp *p + 700 * 8\n\t");
}

extern "C" DLL_EXPORT SockaddrInGetAddrText()
{
asm("jmp *p + 701 * 8\n\t");
}

extern "C" DLL_EXPORT SockaddrInParse()
{
asm("jmp *p + 702 * 8\n\t");
}

extern "C" DLL_EXPORT SockaddrInParse2()
{
asm("jmp *p + 703 * 8\n\t");
}

extern "C" DLL_EXPORT SockaddrInSetAddrText()
{
asm("jmp *p + 704 * 8\n\t");
}

extern "C" DLL_EXPORT SocketAccept()
{
asm("jmp *p + 705 * 8\n\t");
}

extern "C" DLL_EXPORT SocketBind()
{
asm("jmp *p + 706 * 8\n\t");
}

extern "C" DLL_EXPORT SocketCallback()
{
asm("jmp *p + 707 * 8\n\t");
}

extern "C" DLL_EXPORT SocketClose()
{
asm("jmp *p + 708 * 8\n\t");
}

extern "C" DLL_EXPORT SocketConnect()
{
asm("jmp *p + 709 * 8\n\t");
}

extern "C" DLL_EXPORT SocketControl()
{
asm("jmp *p + 710 * 8\n\t");
}

extern "C" DLL_EXPORT SocketCreate()
{
asm("jmp *p + 711 * 8\n\t");
}

extern "C" DLL_EXPORT SocketDestroy()
{
asm("jmp *p + 712 * 8\n\t");
}

extern "C" DLL_EXPORT SocketGetLocalAddr()
{
asm("jmp *p + 713 * 8\n\t");
}

extern "C" DLL_EXPORT SocketHost()
{
asm("jmp *p + 714 * 8\n\t");
}

extern "C" DLL_EXPORT SocketHtonl()
{
asm("jmp *p + 715 * 8\n\t");
}

extern "C" DLL_EXPORT SocketHtons()
{
asm("jmp *p + 716 * 8\n\t");
}

extern "C" DLL_EXPORT SocketImport()
{
asm("jmp *p + 717 * 8\n\t");
}

extern "C" DLL_EXPORT SocketInAddrGetText()
{
asm("jmp *p + 718 * 8\n\t");
}

extern "C" DLL_EXPORT SocketInTextGetAddr()
{
asm("jmp *p + 719 * 8\n\t");
}

extern "C" DLL_EXPORT SocketInfo()
{
asm("jmp *p + 720 * 8\n\t");
}

extern "C" DLL_EXPORT SocketListen()
{
asm("jmp *p + 721 * 8\n\t");
}

extern "C" DLL_EXPORT SocketLookup()
{
asm("jmp *p + 722 * 8\n\t");
}

extern "C" DLL_EXPORT SocketNtohl()
{
asm("jmp *p + 723 * 8\n\t");
}

extern "C" DLL_EXPORT SocketNtohs()
{
asm("jmp *p + 724 * 8\n\t");
}

extern "C" DLL_EXPORT SocketOpen()
{
asm("jmp *p + 725 * 8\n\t");
}

extern "C" DLL_EXPORT SocketRecvfrom()
{
asm("jmp *p + 726 * 8\n\t");
}

extern "C" DLL_EXPORT SocketRelease()
{
asm("jmp *p + 727 * 8\n\t");
}

extern "C" DLL_EXPORT SocketSendto()
{
asm("jmp *p + 728 * 8\n\t");
}

extern "C" DLL_EXPORT SocketShutdown()
{
asm("jmp *p + 729 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldDelete()
{
asm("jmp *p + 730 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldDivider()
{
asm("jmp *p + 731 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldDupl()
{
asm("jmp *p + 732 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldFind()
{
asm("jmp *p + 733 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldFind2()
{
asm("jmp *p + 734 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldFindIdx()
{
asm("jmp *p + 735 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldFindNext()
{
asm("jmp *p + 736 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldFirst()
{
asm("jmp *p + 737 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldFormat()
{
asm("jmp *p + 738 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldGetAddress()
{
asm("jmp *p + 739 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldGetBinary()
{
asm("jmp *p + 740 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldGetDate()
{
asm("jmp *p + 741 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldGetDelim()
{
asm("jmp *p + 742 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldGetEpoch()
{
asm("jmp *p + 743 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldGetFlags()
{
asm("jmp *p + 744 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldGetFloat()
{
asm("jmp *p + 745 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldGetNumber()
{
asm("jmp *p + 746 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldGetNumber64()
{
asm("jmp *p + 747 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldGetRaw()
{
asm("jmp *p + 748 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldGetString()
{
asm("jmp *p + 749 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldGetStructure()
{
asm("jmp *p + 750 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldGetStructureOffsets()
{
asm("jmp *p + 751 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldGetToken()
{
asm("jmp *p + 752 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldMerge()
{
asm("jmp *p + 753 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldPrintf()
{
asm("jmp *p + 754 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldRename()
{
asm("jmp *p + 755 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldSetAddress()
{
asm("jmp *p + 756 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldSetBinary()
{
asm("jmp *p + 757 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldSetBinary7()
{
asm("jmp *p + 758 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldSetDate()
{
asm("jmp *p + 759 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldSetEpoch()
{
asm("jmp *p + 760 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldSetFlags()
{
asm("jmp *p + 761 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldSetFloat()
{
asm("jmp *p + 762 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldSetNumber()
{
asm("jmp *p + 763 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldSetNumber64()
{
asm("jmp *p + 764 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldSetRaw()
{
asm("jmp *p + 765 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldSetString()
{
asm("jmp *p + 766 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldSetStructure()
{
asm("jmp *p + 767 * 8\n\t");
}

extern "C" DLL_EXPORT TagFieldSetToken()
{
asm("jmp *p + 768 * 8\n\t");
}

extern "C" DLL_EXPORT Utf8DecodeToUCS2()
{
asm("jmp *p + 769 * 8\n\t");
}

extern "C" DLL_EXPORT Utf8EncodeFrom8Bit()
{
asm("jmp *p + 770 * 8\n\t");
}

extern "C" DLL_EXPORT Utf8EncodeFromUCS2()
{
asm("jmp *p + 771 * 8\n\t");
}

extern "C" DLL_EXPORT Utf8EncodeFromUCS2CodePt()
{
asm("jmp *p + 772 * 8\n\t");
}

extern "C" DLL_EXPORT Utf8Replace()
{
asm("jmp *p + 773 * 8\n\t");
}

extern "C" DLL_EXPORT Utf8StrLen()
{
asm("jmp *p + 774 * 8\n\t");
}

extern "C" DLL_EXPORT Utf8Strip()
{
asm("jmp *p + 775 * 8\n\t");
}

extern "C" DLL_EXPORT Utf8TranslateTo8Bit()
{
asm("jmp *p + 776 * 8\n\t");
}

extern "C" DLL_EXPORT VoipCodecControl()
{
asm("jmp *p + 777 * 8\n\t");
}

extern "C" DLL_EXPORT VoipCodecCreate()
{
asm("jmp *p + 778 * 8\n\t");
}

extern "C" DLL_EXPORT VoipCodecDecode()
{
asm("jmp *p + 779 * 8\n\t");
}

extern "C" DLL_EXPORT VoipCodecDestroy()
{
asm("jmp *p + 780 * 8\n\t");
}

extern "C" DLL_EXPORT VoipCodecEncode()
{
asm("jmp *p + 781 * 8\n\t");
}

extern "C" DLL_EXPORT VoipCodecRegister()
{
asm("jmp *p + 782 * 8\n\t");
}

extern "C" DLL_EXPORT VoipCodecReset()
{
asm("jmp *p + 783 * 8\n\t");
}

extern "C" DLL_EXPORT VoipCodecStatus()
{
asm("jmp *p + 784 * 8\n\t");
}

extern "C" DLL_EXPORT VoipConnect()
{
asm("jmp *p + 785 * 8\n\t");
}

extern "C" DLL_EXPORT VoipControl()
{
asm("jmp *p + 786 * 8\n\t");
}

extern "C" DLL_EXPORT VoipDisconnect()
{
asm("jmp *p + 787 * 8\n\t");
}

extern "C" DLL_EXPORT VoipDisconnect2()
{
asm("jmp *p + 788 * 8\n\t");
}

extern "C" DLL_EXPORT VoipGetProfileStat()
{
asm("jmp *p + 789 * 8\n\t");
}

extern "C" DLL_EXPORT VoipGetProfileTime()
{
asm("jmp *p + 790 * 8\n\t");
}

extern "C" DLL_EXPORT VoipGetRef()
{
asm("jmp *p + 791 * 8\n\t");
}

extern "C" DLL_EXPORT VoipGroupConnect()
{
asm("jmp *p + 792 * 8\n\t");
}

extern "C" DLL_EXPORT VoipGroupControl()
{
asm("jmp *p + 793 * 8\n\t");
}

extern "C" DLL_EXPORT VoipGroupCreate()
{
asm("jmp *p + 794 * 8\n\t");
}

extern "C" DLL_EXPORT VoipGroupDestroy()
{
asm("jmp *p + 795 * 8\n\t");
}

extern "C" DLL_EXPORT VoipGroupDisconnect()
{
asm("jmp *p + 796 * 8\n\t");
}

extern "C" DLL_EXPORT VoipGroupIsMutedByClientId()
{
asm("jmp *p + 797 * 8\n\t");
}

extern "C" DLL_EXPORT VoipGroupIsMutedByConnId()
{
asm("jmp *p + 798 * 8\n\t");
}

extern "C" DLL_EXPORT VoipGroupLocal()
{
asm("jmp *p + 799 * 8\n\t");
}

extern "C" DLL_EXPORT VoipGroupMuteByClientId()
{
asm("jmp *p + 800 * 8\n\t");
}

extern "C" DLL_EXPORT VoipGroupMuteByConnId()
{
asm("jmp *p + 801 * 8\n\t");
}

extern "C" DLL_EXPORT VoipGroupRemote()
{
asm("jmp *p + 802 * 8\n\t");
}

extern "C" DLL_EXPORT VoipGroupResume()
{
asm("jmp *p + 803 * 8\n\t");
}

extern "C" DLL_EXPORT VoipGroupSetConnSharingEventCallback()
{
asm("jmp *p + 804 * 8\n\t");
}

extern "C" DLL_EXPORT VoipGroupSetEventCallback()
{
asm("jmp *p + 805 * 8\n\t");
}

extern "C" DLL_EXPORT VoipGroupStatus()
{
asm("jmp *p + 806 * 8\n\t");
}

extern "C" DLL_EXPORT VoipGroupSuspend()
{
asm("jmp *p + 807 * 8\n\t");
}

extern "C" DLL_EXPORT VoipLocal()
{
asm("jmp *p + 808 * 8\n\t");
}

extern "C" DLL_EXPORT VoipMicrophone()
{
asm("jmp *p + 809 * 8\n\t");
}

extern "C" DLL_EXPORT VoipRemote()
{
asm("jmp *p + 810 * 8\n\t");
}

extern "C" DLL_EXPORT VoipRemove()
{
asm("jmp *p + 811 * 8\n\t");
}

extern "C" DLL_EXPORT VoipResetChannels()
{
asm("jmp *p + 812 * 8\n\t");
}

extern "C" DLL_EXPORT VoipSelectChannel()
{
asm("jmp *p + 813 * 8\n\t");
}

extern "C" DLL_EXPORT VoipSetEventCallback()
{
asm("jmp *p + 814 * 8\n\t");
}

extern "C" DLL_EXPORT VoipSetLocalUser()
{
asm("jmp *p + 815 * 8\n\t");
}

extern "C" DLL_EXPORT VoipShutdown()
{
asm("jmp *p + 816 * 8\n\t");
}

extern "C" DLL_EXPORT VoipSpeaker()
{
asm("jmp *p + 817 * 8\n\t");
}

extern "C" DLL_EXPORT VoipSpkrCallback()
{
asm("jmp *p + 818 * 8\n\t");
}

extern "C" DLL_EXPORT VoipStartup()
{
asm("jmp *p + 819 * 8\n\t");
}

extern "C" DLL_EXPORT VoipStatus()
{
asm("jmp *p + 820 * 8\n\t");
}

extern "C" DLL_EXPORT VoipTunnelCallback()
{
asm("jmp *p + 821 * 8\n\t");
}

extern "C" DLL_EXPORT VoipTunnelClientListAdd()
{
asm("jmp *p + 822 * 8\n\t");
}

extern "C" DLL_EXPORT VoipTunnelClientListAdd2()
{
asm("jmp *p + 823 * 8\n\t");
}

extern "C" DLL_EXPORT VoipTunnelClientListDel()
{
asm("jmp *p + 824 * 8\n\t");
}

extern "C" DLL_EXPORT VoipTunnelClientListMatchAddr()
{
asm("jmp *p + 825 * 8\n\t");
}

extern "C" DLL_EXPORT VoipTunnelClientListMatchFunc()
{
asm("jmp *p + 826 * 8\n\t");
}

extern "C" DLL_EXPORT VoipTunnelClientListMatchId()
{
asm("jmp *p + 827 * 8\n\t");
}

extern "C" DLL_EXPORT VoipTunnelClientListMatchIndex()
{
asm("jmp *p + 828 * 8\n\t");
}

extern "C" DLL_EXPORT VoipTunnelClientListMatchSockaddr()
{
asm("jmp *p + 829 * 8\n\t");
}

extern "C" DLL_EXPORT VoipTunnelClientRefreshSendMask()
{
asm("jmp *p + 830 * 8\n\t");
}

extern "C" DLL_EXPORT VoipTunnelControl()
{
asm("jmp *p + 831 * 8\n\t");
}

extern "C" DLL_EXPORT VoipTunnelCreate()
{
asm("jmp *p + 832 * 8\n\t");
}

extern "C" DLL_EXPORT VoipTunnelDestroy()
{
asm("jmp *p + 833 * 8\n\t");
}

extern "C" DLL_EXPORT VoipTunnelGameListAdd()
{
asm("jmp *p + 834 * 8\n\t");
}

extern "C" DLL_EXPORT VoipTunnelGameListDel()
{
asm("jmp *p + 835 * 8\n\t");
}

extern "C" DLL_EXPORT VoipTunnelStatus()
{
asm("jmp *p + 836 * 8\n\t");
}

extern "C" DLL_EXPORT VoipTunnelUpdate()
{
asm("jmp *p + 837 * 8\n\t");
}

extern "C" DLL_EXPORT WebLogConfigure()
{
asm("jmp *p + 838 * 8\n\t");
}

extern "C" DLL_EXPORT WebLogControl()
{
asm("jmp *p + 839 * 8\n\t");
}

extern "C" DLL_EXPORT WebLogCreate()
{
asm("jmp *p + 840 * 8\n\t");
}

extern "C" DLL_EXPORT WebLogDebugHook()
{
asm("jmp *p + 841 * 8\n\t");
}

extern "C" DLL_EXPORT WebLogDestroy()
{
asm("jmp *p + 842 * 8\n\t");
}

extern "C" DLL_EXPORT WebLogPrintf()
{
asm("jmp *p + 843 * 8\n\t");
}

extern "C" DLL_EXPORT WebLogStart()
{
asm("jmp *p + 844 * 8\n\t");
}

extern "C" DLL_EXPORT WebLogStop()
{
asm("jmp *p + 845 * 8\n\t");
}

extern "C" DLL_EXPORT WebLogUpdate()
{
asm("jmp *p + 846 * 8\n\t");
}

extern "C" DLL_EXPORT WebOfferAction()
{
asm("jmp *p + 847 * 8\n\t");
}

extern "C" DLL_EXPORT WebOfferClear()
{
asm("jmp *p + 848 * 8\n\t");
}

extern "C" DLL_EXPORT WebOfferCommand()
{
asm("jmp *p + 849 * 8\n\t");
}

extern "C" DLL_EXPORT WebOfferCreate()
{
asm("jmp *p + 850 * 8\n\t");
}

extern "C" DLL_EXPORT WebOfferDestroy()
{
asm("jmp *p + 851 * 8\n\t");
}

extern "C" DLL_EXPORT WebOfferExecute()
{
asm("jmp *p + 852 * 8\n\t");
}

extern "C" DLL_EXPORT WebOfferGetAlert()
{
asm("jmp *p + 853 * 8\n\t");
}

extern "C" DLL_EXPORT WebOfferGetArticles()
{
asm("jmp *p + 854 * 8\n\t");
}

extern "C" DLL_EXPORT WebOfferGetBusy()
{
asm("jmp *p + 855 * 8\n\t");
}

extern "C" DLL_EXPORT WebOfferGetBusy2()
{
asm("jmp *p + 856 * 8\n\t");
}

extern "C" DLL_EXPORT WebOfferGetCredit()
{
asm("jmp *p + 857 * 8\n\t");
}

extern "C" DLL_EXPORT WebOfferGetForm()
{
asm("jmp *p + 858 * 8\n\t");
}

extern "C" DLL_EXPORT WebOfferGetMarketplace()
{
asm("jmp *p + 859 * 8\n\t");
}

extern "C" DLL_EXPORT WebOfferGetMedia()
{
asm("jmp *p + 860 * 8\n\t");
}

extern "C" DLL_EXPORT WebOfferGetMenu()
{
asm("jmp *p + 861 * 8\n\t");
}

extern "C" DLL_EXPORT WebOfferGetNews()
{
asm("jmp *p + 862 * 8\n\t");
}

extern "C" DLL_EXPORT WebOfferGetPromo()
{
asm("jmp *p + 863 * 8\n\t");
}

extern "C" DLL_EXPORT WebOfferGetStory()
{
asm("jmp *p + 864 * 8\n\t");
}

extern "C" DLL_EXPORT WebOfferHttp()
{
asm("jmp *p + 865 * 8\n\t");
}

extern "C" DLL_EXPORT WebOfferHttpComplete()
{
asm("jmp *p + 866 * 8\n\t");
}

extern "C" DLL_EXPORT WebOfferParamList()
{
asm("jmp *p + 867 * 8\n\t");
}

extern "C" DLL_EXPORT WebOfferResource()
{
asm("jmp *p + 868 * 8\n\t");
}

extern "C" DLL_EXPORT WebOfferResultData()
{
asm("jmp *p + 869 * 8\n\t");
}

extern "C" DLL_EXPORT WebOfferSetCredit()
{
asm("jmp *p + 870 * 8\n\t");
}

extern "C" DLL_EXPORT WebOfferSetForm()
{
asm("jmp *p + 871 * 8\n\t");
}

extern "C" DLL_EXPORT WebOfferSetPromo()
{
asm("jmp *p + 872 * 8\n\t");
}

extern "C" DLL_EXPORT WebOfferSetup()
{
asm("jmp *p + 873 * 8\n\t");
}

extern "C" DLL_EXPORT WebOfferUpdate()
{
asm("jmp *p + 874 * 8\n\t");
}

extern "C" DLL_EXPORT XmlAttrSetAddr()
{
asm("jmp *p + 875 * 8\n\t");
}

extern "C" DLL_EXPORT XmlAttrSetDate()
{
asm("jmp *p + 876 * 8\n\t");
}

extern "C" DLL_EXPORT XmlAttrSetFloat()
{
asm("jmp *p + 877 * 8\n\t");
}

extern "C" DLL_EXPORT XmlAttrSetInt()
{
asm("jmp *p + 878 * 8\n\t");
}

extern "C" DLL_EXPORT XmlAttrSetString()
{
asm("jmp *p + 879 * 8\n\t");
}

extern "C" DLL_EXPORT XmlAttrSetStringRaw()
{
asm("jmp *p + 880 * 8\n\t");
}

extern "C" DLL_EXPORT XmlAttribGetDate()
{
asm("jmp *p + 881 * 8\n\t");
}

extern "C" DLL_EXPORT XmlAttribGetInteger()
{
asm("jmp *p + 882 * 8\n\t");
}

extern "C" DLL_EXPORT XmlAttribGetString()
{
asm("jmp *p + 883 * 8\n\t");
}

extern "C" DLL_EXPORT XmlAttribGetToken()
{
asm("jmp *p + 884 * 8\n\t");
}

extern "C" DLL_EXPORT XmlBufSizeIncrease()
{
asm("jmp *p + 885 * 8\n\t");
}

extern "C" DLL_EXPORT XmlComplete()
{
asm("jmp *p + 886 * 8\n\t");
}

extern "C" DLL_EXPORT XmlContentGetAddress()
{
asm("jmp *p + 887 * 8\n\t");
}

extern "C" DLL_EXPORT XmlContentGetBinary()
{
asm("jmp *p + 888 * 8\n\t");
}

extern "C" DLL_EXPORT XmlContentGetDate()
{
asm("jmp *p + 889 * 8\n\t");
}

extern "C" DLL_EXPORT XmlContentGetInteger()
{
asm("jmp *p + 890 * 8\n\t");
}

extern "C" DLL_EXPORT XmlContentGetString()
{
asm("jmp *p + 891 * 8\n\t");
}

extern "C" DLL_EXPORT XmlContentGetToken()
{
asm("jmp *p + 892 * 8\n\t");
}

extern "C" DLL_EXPORT XmlConvEpoch2Date()
{
asm("jmp *p + 893 * 8\n\t");
}

extern "C" DLL_EXPORT XmlElemAddDate()
{
asm("jmp *p + 894 * 8\n\t");
}

extern "C" DLL_EXPORT XmlElemAddFloat()
{
asm("jmp *p + 895 * 8\n\t");
}

extern "C" DLL_EXPORT XmlElemAddInt()
{
asm("jmp *p + 896 * 8\n\t");
}

extern "C" DLL_EXPORT XmlElemAddString()
{
asm("jmp *p + 897 * 8\n\t");
}

extern "C" DLL_EXPORT XmlElemSetAddr()
{
asm("jmp *p + 898 * 8\n\t");
}

extern "C" DLL_EXPORT XmlElemSetDate()
{
asm("jmp *p + 899 * 8\n\t");
}

extern "C" DLL_EXPORT XmlElemSetInt()
{
asm("jmp *p + 900 * 8\n\t");
}

extern "C" DLL_EXPORT XmlElemSetString()
{
asm("jmp *p + 901 * 8\n\t");
}

extern "C" DLL_EXPORT XmlElemSetStringRaw()
{
asm("jmp *p + 902 * 8\n\t");
}

extern "C" DLL_EXPORT XmlFind()
{
asm("jmp *p + 903 * 8\n\t");
}

extern "C" DLL_EXPORT XmlFinish()
{
asm("jmp *p + 904 * 8\n\t");
}

extern "C" DLL_EXPORT XmlFormatPrintf()
{
asm("jmp *p + 905 * 8\n\t");
}

extern "C" DLL_EXPORT XmlFormatVPrintf()
{
asm("jmp *p + 906 * 8\n\t");
}

extern "C" DLL_EXPORT XmlInit()
{
asm("jmp *p + 907 * 8\n\t");
}

extern "C" DLL_EXPORT XmlNext()
{
asm("jmp *p + 908 * 8\n\t");
}

extern "C" DLL_EXPORT XmlSkip()
{
asm("jmp *p + 909 * 8\n\t");
}

extern "C" DLL_EXPORT XmlStep()
{
asm("jmp *p + 910 * 8\n\t");
}

extern "C" DLL_EXPORT XmlTagEnd()
{
asm("jmp *p + 911 * 8\n\t");
}

extern "C" DLL_EXPORT XmlTagStart()
{
asm("jmp *p + 912 * 8\n\t");
}

extern "C" DLL_EXPORT XmlValidate()
{
asm("jmp *p + 913 * 8\n\t");
}

extern "C" DLL_EXPORT _BuddyApiSetTalkToXbox()
{
asm("jmp *p + 914 * 8\n\t");
}

extern "C" DLL_EXPORT ds_localtime()
{
asm("jmp *p + 915 * 8\n\t");
}

extern "C" DLL_EXPORT ds_plattimetotime()
{
asm("jmp *p + 916 * 8\n\t");
}

extern "C" DLL_EXPORT ds_plattimetotimems()
{
asm("jmp *p + 917 * 8\n\t");
}

extern "C" DLL_EXPORT ds_secstostr()
{
asm("jmp *p + 918 * 8\n\t");
}

extern "C" DLL_EXPORT ds_secstotime()
{
asm("jmp *p + 919 * 8\n\t");
}

extern "C" DLL_EXPORT ds_snzprintf()
{
asm("jmp *p + 920 * 8\n\t");
}

extern "C" DLL_EXPORT ds_strcmpwc()
{
asm("jmp *p + 921 * 8\n\t");
}

extern "C" DLL_EXPORT ds_stricmp()
{
asm("jmp *p + 922 * 8\n\t");
}

extern "C" DLL_EXPORT ds_stricmpwc()
{
asm("jmp *p + 923 * 8\n\t");
}

extern "C" DLL_EXPORT ds_stristr()
{
asm("jmp *p + 924 * 8\n\t");
}

extern "C" DLL_EXPORT ds_strnicmp()
{
asm("jmp *p + 925 * 8\n\t");
}

extern "C" DLL_EXPORT ds_strnzcat()
{
asm("jmp *p + 926 * 8\n\t");
}

extern "C" DLL_EXPORT ds_strnzcpy()
{
asm("jmp *p + 927 * 8\n\t");
}

extern "C" DLL_EXPORT ds_strsubzcat()
{
asm("jmp *p + 928 * 8\n\t");
}

extern "C" DLL_EXPORT ds_strsubzcpy()
{
asm("jmp *p + 929 * 8\n\t");
}

extern "C" DLL_EXPORT ds_strtotime()
{
asm("jmp *p + 930 * 8\n\t");
}

extern "C" DLL_EXPORT ds_strtotime2()
{
asm("jmp *p + 931 * 8\n\t");
}

extern "C" DLL_EXPORT ds_timeinsecs()
{
asm("jmp *p + 932 * 8\n\t");
}

extern "C" DLL_EXPORT ds_timetosecs()
{
asm("jmp *p + 933 * 8\n\t");
}

extern "C" DLL_EXPORT ds_timetostr()
{
asm("jmp *p + 934 * 8\n\t");
}

extern "C" DLL_EXPORT ds_timezone()
{
asm("jmp *p + 935 * 8\n\t");
}

extern "C" DLL_EXPORT ds_vsnprintf()
{
asm("jmp *p + 936 * 8\n\t");
}

extern "C" DLL_EXPORT ds_vsnzprintf()
{
asm("jmp *p + 937 * 8\n\t");
}
