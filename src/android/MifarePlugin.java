/**
 * Copyright (C) 2015 Frosty Elk AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package se.frostyelk.cordova.mifare;

import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.NfcA;
import com.nxp.nfclib.classic.MFClassic;
import com.nxp.nfclib.exceptions.SmartCardException;
import com.nxp.nfclib.icode.*;
import com.nxp.nfclib.ntag.*;
import com.nxp.nfclib.plus.PlusSL1;
import com.nxp.nfclib.ultralight.Ultralight;
import com.nxp.nfclib.ultralight.UltralightC;
import com.nxp.nfclib.ultralight.UltralightEV1;
import com.nxp.nfclib.utils.NxpLogUtils;
import com.nxp.nfclib.utils.Utilities;
import com.nxp.nfcliblite.Interface.NxpNfcLibLite;
import com.nxp.nfcliblite.Interface.Nxpnfcliblitecallback;
import com.nxp.nfcliblite.cards.DESFire;
import com.nxp.nfcliblite.cards.Plus;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.PluginResult;
import org.apache.cordova.PluginResult.Status;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;


import android.util.Log;

/**
 * This class represents the native implementation for the MIFARE Cordova plugin.
 */
public class MifarePlugin extends CordovaPlugin {

    private static final String LOGTAG = "MifarePlugin";
    private static final String ACTION_INIT = "init";
    private static final String ACTION_WRITE_TAG_DATA = "writeTag";
    private static final String TAG_EVENT_DETECTED = "onTagDetected";
    private static final String TAG_EVENT_ERROR = "onTagError";
    private static final String TAG_EVENT_ERROR_TYPE_SECURITY = "Security";
    private static final String TAG_EVENT_ERROR_TYPE_IOREAD = "IORead";
    private static final String TAG_EVENT_ERROR_TYPE_CARD = "Card";
    private static final String TAG_EVENT_ERROR_TYPE_UNSUPPORTED = "Unsupported";
    private static final int UNIVERSAL_NUMBER = 42;
    private static final int MAX_FAST_READ_PAGES = 50;
    private static String TAG = "MifarePLugin";

    private String password;
    private byte[] payload;
    private NTag nTag;
    private Tag tagInfo;
    private Intent initializeIntent;

    // It seems that password errors returns as IOException instead of SmartCardException?!
    private boolean checkForPasswordSentAtIOError = false;

    private void sendEventToWebView(String eventName, JSONObject jsonData) {
        final String url = "javascript:cordova.fireDocumentEvent('" + eventName + "', " + jsonData.toString() + ");";
        NxpLogUtils.i(LOGTAG, "sendEventToWebView: " + url);

        if ((webView != null) && (webView.getView() != null)) {
            webView.getView().post(new Runnable() {

                @Override
                public void run() {
                    webView.loadUrl(url);
                }
            });
        } else {
            NxpLogUtils.w(TAG, "sendEventToWebView() without a vebview active.");
        }
    }

    @Override
    public void pluginInitialize() {
        super.pluginInitialize();

        // Get and set the lib Singleton instance
        NxpNfcLibLite.getInstance().registerActivity(cordova.getActivity());


        // The default for NfcLogUtils logging is off, turn it on
        NxpLogUtils.enableLog();
        NxpLogUtils.i(LOGTAG, "MIFARE Cordova plugin pluginInitialize");

        initializeIntent = cordova.getActivity().getIntent();
        if (initializeIntent != null) {
            NxpLogUtils.i(TAG, "pluginInitialize Intent: " + initializeIntent.toString());
            NxpLogUtils.i(TAG, "pluginInitialize Action: " + initializeIntent.getAction());
        } else {
            NxpLogUtils.i(LOGTAG, "No Intent in pluginInitialize");
        }
    }
	
	/*
    @Override
    public void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        NxpLogUtils.i(TAG, "onNewIntent Intent: " + intent.toString());
        NxpLogUtils.i(TAG, "onNewIntent Action: " + intent.getAction());

        tagInfo = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);

        // Only act on intents from a tag
        if (tagInfo == null) {
            return;
        }

        NxpLogUtils.i(TAG, "Tag info: " + tagInfo.toString());

        Nxpnfcliblitecallback callback = new Nxpnfcliblitecallback() {
            @Override
            public void onNTag210CardDetected(NTag210 nTag210) {
                NxpLogUtils.i(TAG, "Found a NTag210 Card!");
                handleCardDetected(nTag210);
            }

            @Override
            public void onNTag213215216CardDetected(NTag213215216 nTag213215216) {
                NxpLogUtils.i(TAG, "Found a NTag213215216 Card!");
                handleCardDetected(nTag213215216);
            }

            @Override
            public void onNTag213F216FCardDetected(NTag213F216F nTag213F216F) {
                NxpLogUtils.i(TAG, "Found a NTag213F216F Card!");
                handleCardDetected(nTag213F216F);
            }

            @Override
            public void onUltraLightCardDetected(Ultralight ultralight) {
                NxpLogUtils.i(TAG, "Found a Ultralight Card!");
				handleUnsupportedCards();
            }

            @Override
            public void onUltraLightCCardDetected(UltralightC ultralightC) {
                NxpLogUtils.i(TAG, "Found a UltralightC Card!");	
				handleUnsupportedCards();
            }

            @Override
            public void onUltraLightEV1CardDetected(UltralightEV1 ultralightEV1) {
                NxpLogUtils.i(TAG, "Found a UltralightEV1 Card!");	
				handleUnsupportedCards();
            }

            @Override
            public void onClassicCardDetected(MFClassic mfClassic) {
                NxpLogUtils.i(TAG, "Found a MFClassic Card!");	
				handleUnsupportedCards();
            }

            @Override
            public void onDESFireCardDetected(DESFire desFire) {
                NxpLogUtils.i(TAG, "Found a DESFire Card!");
				handleUnsupportedCards();
            }

            @Override
            public void onNTag203xCardDetected(NTag203x nTag203x) {
				NxpLogUtils.i(TAG, "Found a NTag203x Card!");   
				handleUnsupportedCards();
            }

            @Override
            public void onNTagI2CCardDetected(NTagI2C nTagI2C) {
                NxpLogUtils.i(TAG, "Found a NTagI2C Card!");   
				handleUnsupportedCards();
            }

            @Override
            public void onICodeSLIDetected(ICodeSLI iCodeSLI) {
                NxpLogUtils.i(TAG, "Found a ICodeSLI Card!");   
				handleUnsupportedCards();
            }

            @Override
            public void onICodeSLISDetected(ICodeSLIS iCodeSLIS) {
                NxpLogUtils.i(TAG, "Found a ICodeSLIS Card!");   
				handleUnsupportedCards();
            }

            @Override
            public void onICodeSLILDetected(ICodeSLIL iCodeSLIL) {
                NxpLogUtils.i(TAG, "Found a ICodeSLIL Card!");   
				handleUnsupportedCards();
            }

            @Override
            public void onICodeSLIXDetected(ICodeSLIX iCodeSLIX) {
                NxpLogUtils.i(TAG, "Found a ICodeSLIX Card!");   
				handleUnsupportedCards();
            }

            @Override
            public void onICodeSLIXSDetected(ICodeSLIXS iCodeSLIXS) {
                NxpLogUtils.i(TAG, "Found a ICodeSLIXS Card!");   
				handleUnsupportedCards();
            }

            @Override
            public void onICodeSLIXLDetected(ICodeSLIXL iCodeSLIXL) {
                NxpLogUtils.i(TAG, "Found a ICodeSLIXL Card!");   
				handleUnsupportedCards();
            }

            @Override
            public void onPlusCardDetected(Plus plus) {
                NxpLogUtils.i(TAG, "Found a Plus Card!");   
				handleUnsupportedCards();
            }

            @Override
            public void onPlusSL1CardDetected(PlusSL1 plusSL1) {
                NxpLogUtils.i(TAG, "Found a PlusSLI Card!");   
				handleUnsupportedCards();
            }

            @Override
            public void onICodeSLIX2Detected(ICodeSLIX2 iCodeSLIX2) {
                NxpLogUtils.i(TAG, "Found a ICodeSLIX2 Card!");   
				handleUnsupportedCards();
            }
			
			//@Override
			//public void onCardNotSupported(Tag tag) {
			//	NxpLogUtils.i(TAG, "Found Not Supported Card!");   
		//		handleUnsupportedCards();
		//		handleUnsupportedCards();
		//	}
			
        };

        NxpNfcLibLite.getInstance().filterIntent(intent, callback);
    } */

	@Override
    public void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        NxpLogUtils.i(TAG, "onNewIntent Intent: " + intent.toString());
        NxpLogUtils.i(TAG, "onNewIntent Action: " + intent.getAction());
		
        tagInfo = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
		byte[] uid = paramIntent.getByteArrayExtra(NfcAdapter.EXTRA_ID);
		
		NfcA ntag215 = NfcA.get(tagInfo);
		Log.d(TAG, "ntag215");
		Log.d(TAG, ntag215);
		
        // Only act on intents from a tag
        if (tagInfo == null) {
            return;
        }

        NxpLogUtils.i(TAG, "Tag info: " + tagInfo.toString());
		
		writeAndProtectTag(intent, "Hello World");
		
        //NxpNfcLibLite.getInstance().filterIntent(intent, callback);
    }
	

    /**
     *
     */
    private void handleUnsupportedCards() {
        JSONObject result = new JSONObject();
        try {
            result.put("nfcType", TAG_EVENT_ERROR_TYPE_UNSUPPORTED);
            result.put("nfcCode", UNIVERSAL_NUMBER);
            result.put("nfcMessage", "Unsupported tag detected");
			NxpLogUtils.i(TAG, "Unsupported tag detected!"); 
        } catch (JSONException e) {
            NxpLogUtils.v(TAG, "JSONException: " + e.getMessage());
        }

        sendEventToWebView(TAG_EVENT_ERROR, result);
    }


    /**
     * @param nTag210 The tag
     */
    private void handleCardDetected(NTag210 nTag210) {

        nTag = nTag210;

        byte pack[] = {0, 0};
        byte pw[] = password.getBytes();

        try {

            nTag210.connect();
            NxpLogUtils.i(TAG, "Connect successful!");

            if (!"".equals(password)) {
                NxpLogUtils.i(TAG, "Trying Authenticate with Password[]: " + Utilities.dumpBytes(pw));
                checkForPasswordSentAtIOError = true;
                nTag210.authenticatePwd(pw, pack);
                checkForPasswordSentAtIOError = false;
                NxpLogUtils.i(TAG, "Authenticate successful!");
            }

            // Read full memory
            // One page = 4 bytes
            int userAvailableMemory = nTag.getCardDetails().freeMemory;
            int numbPages = userAvailableMemory / 4;
            NxpLogUtils.i(TAG, "Card Details User Memory size: " + userAvailableMemory);

            // Older devices can only read a limited number of pages,
            // some testing ended up with the number MAX_FAST_READ_PAGES
            int startPage = 0;
            int endPage = numbPages >= MAX_FAST_READ_PAGES ? MAX_FAST_READ_PAGES - 1 : numbPages - 1;
            boolean doneReading = false;

            payload = new byte[]{};

            while (!doneReading) {
                payload = Utilities.append(payload, nTag210.fastRead(startPage, endPage));

                if (endPage >= numbPages - 1) {
                    doneReading = true;
                } else {
                    startPage = endPage + 1;
                    endPage = (endPage + MAX_FAST_READ_PAGES) >= numbPages ? numbPages - 1 : endPage + MAX_FAST_READ_PAGES;
                }
            }

            NxpLogUtils.i(TAG, "Length of payload read " + payload.length);

            JSONObject result = new JSONObject();
            JSONArray tagUID;

            try {
                tagUID = new JSONArray(nTag.getUID());
                result.put("tagUID", tagUID);
                result.put("tagName", nTag.getTagName());

                JSONArray payloadArray = new JSONArray(payload);
                result.put("payload", payloadArray);
                payload = null;
				
				NxpLogUtils.i(TAG, "Write Successful!");
				
                sendEventToWebView(TAG_EVENT_DETECTED, result);
            } catch (JSONException e) {
                NxpLogUtils.v(TAG, "JSONException: " + e.getMessage());
            }

        } catch (SmartCardException e) {
            JSONObject result = new JSONObject();
            try {
                if (e.getExcetionType() == SmartCardException.EXCEPTIONTYPE_SECURITY) {
                    result.put("nfcType", TAG_EVENT_ERROR_TYPE_SECURITY);
                } else {
                    result.put("nfcType", TAG_EVENT_ERROR_TYPE_CARD);
                }
				
				NxpLogUtils.i(TAG, "Write failed SmartCardException fired!");
				
                result.put("nfcCode", e.getErrorCode());
                result.put("nfcMessage", e.getMessage());
            } catch (JSONException e1) {
                NxpLogUtils.v(TAG, "JSONException: " + e1.getMessage());
            }

            sendEventToWebView(TAG_EVENT_ERROR, result);
        } catch (IOException e) {
            JSONObject result = new JSONObject();
            try {
                // Ugly hack here to give a better response to pw errors
                if (checkForPasswordSentAtIOError) {
                    result.put("nfcType", TAG_EVENT_ERROR_TYPE_SECURITY);
                    result.put("nfcCode", UNIVERSAL_NUMBER);
                    result.put("nfcMessage", "Password Authentication failed");
                    checkForPasswordSentAtIOError = false;
                } else {
                    result.put("nfcType", TAG_EVENT_ERROR_TYPE_IOREAD);
                    result.put("nfcCode", UNIVERSAL_NUMBER);
                    result.put("nfcMessage", e.getMessage());

                }
				
				NxpLogUtils.i(TAG, "Write failed IOException fired!");
				
            } catch (JSONException e1) {
                NxpLogUtils.v(TAG, "JSONException: " + e1.getMessage());
            }

            sendEventToWebView(TAG_EVENT_ERROR, result);
        } finally {
            try {
				NxpLogUtils.i(TAG, "Tag Closed!");
                nTag210.close();
            } catch (IOException e) {
                NxpLogUtils.v(TAG, "IOException at close(): " + e.getMessage());
            }
        }

    }


    @Override
    public void onDestroy() {
        super.onDestroy();
        NxpLogUtils.i(LOGTAG, "onDestroy");
    }

    @Override
    public void onPause(boolean multitasking) {
        super.onPause(multitasking);
        NxpLogUtils.i(LOGTAG, "onPause");
        try {
            NxpNfcLibLite.getInstance().stopForeGroundDispatch();
        } catch (IllegalStateException e) {
            NxpLogUtils.w(LOGTAG, "IllegalStateException for stopForeGroundDispatch in onPause, ignoring!");
        }

    }

    @Override
    public void onResume(boolean multitasking) {
        super.onResume(multitasking);
        NxpLogUtils.i(LOGTAG, "onResume");

        try {
            NxpNfcLibLite.getInstance().startForeGroundDispatch();
        } catch (IllegalStateException e) {
            NxpLogUtils.w(LOGTAG, "IllegalStateException for startForeGroundDispatch in onResume, ignoring!");
        }
    }

    /**
     * This is the main method for the MIFARE Plugin. All API calls go through
     * here. This method determines the action, and executes the appropriate
     * call.
     *
     * @param action          The action that the plugin should execute.
     * @param args            The input parameters for the action.
     * @param callbackContext The callback context.
     * @return A PluginResult representing the result of the provided action. A
     * status of INVALID_ACTION is returned if the action is not
     * recognized.
     */
    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        PluginResult result;

        NxpLogUtils.enableLog();
        NxpLogUtils.i(LOGTAG, "MIFARE Cordova plugin execute");

        if (ACTION_INIT.equals(action)) {
            result = init(args.getJSONObject(0), callbackContext);
        } else if (ACTION_WRITE_TAG_DATA.equals(action)) {
            result = writeTag(args.getJSONObject(0), callbackContext);
        } else {
            result = new PluginResult(Status.INVALID_ACTION);
        }

        if (result != null) {
            callbackContext.sendPluginResult(result);
        }

        return true;
    }

    /**
     * Initialize the plugin with options
     *
     * @param options         Options {password: tag password}
     * @param callbackContext Callback
     * @return PluginResult
     */
    private PluginResult init(final JSONObject options, final CallbackContext callbackContext) {
        // Start the dispatch here, Cordova will not send onResume at first start
        if (NxpNfcLibLite.getInstance() != null) {
            NxpLogUtils.i(LOGTAG, "Starting startForeGroundDispatch in init");
            try {				
                NxpNfcLibLite.getInstance().startForeGroundDispatch();
				NxpLogUtils.i(LOGTAG, "Started startForeGroundDispatch");
            } catch (IllegalStateException e) {
                NxpLogUtils.w(LOGTAG, "IllegalStateException for startForeGroundDispatch in init, ignoring");
            }
        } else {
            NxpLogUtils.w(LOGTAG, "NxpNfcLibLite.getInstance() == null");
        }

        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                NxpLogUtils.i(LOGTAG, "init: " + options.toString());
                password = options.optString("password", "");
                callbackContext.success("OK");

                // If this is actually a warm start from the NFC activity chooser
                // run the Intent for discovered tags.
                NxpLogUtils.i(LOGTAG, "Checking for NFC in init");
                NxpLogUtils.i(TAG, "init Intent: " + initializeIntent.toString());
                NxpLogUtils.i(TAG, "init Action: " + initializeIntent.getAction());

                if (initializeIntent != null && "android.nfc.action.TECH_DISCOVERED".equals(initializeIntent.getAction())) {
                    NxpLogUtils.i(LOGTAG, "Found NFC in init, running onNewIntent");
                    onNewIntent(initializeIntent);
                }
            }
        });

        return null;
    }


    /**
     * Write tag data
     *
     * @param data            JSONObject
     * @param callbackContext Callback
     * @return PluginResult
     */
    private PluginResult writeTag(final JSONObject data, final CallbackContext callbackContext) {

        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                NxpLogUtils.i(LOGTAG, "writeTag executed");

                // TODO: Implement write tag

                callbackContext.success("OK");
                callbackContext.error("NOK");

            }
        });

        return null;
    }
	
	private void writeAndProtectTag(final Intent intent, final String message) {
		// Run the entire process in its own thread as NfcA.transceive(byte[] data);
		// Should not be run in main thread according to <https://developer.android.com/reference/android/nfc/tech/NfcA.html#transceive(byte[])>
		(new Thread(new Runnable() {
			// Password has to be 4 characters
			// Password Acknowledge has to be 2 characters
			byte[] pwd      = "-_bA".getBytes();
			byte[] pack     = "cC".getBytes();

			@Override
			public void run() {
				// Store tag object for use in NfcA and Ndef
				Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
				// Using NfcA instead of MifareUltralight should make no difference in this method
				NfcA nfca = null;

				// Whole process is put into a big try-catch trying to catch the transceive's IOException
				try {
					nfca = NfcA.get(tag);

					nfca.connect();

					byte[] response;

					// Authenticate with the tag first
					// In case it's already been locked
					try {
						response = nfca.transceive(new byte[]{
								(byte) 0x1B, // PWD_AUTH
								pwd[0], pwd[1], pwd[2], pwd[3]
						});

						// Check if PACK is matching expected PACK
						// This is a (not that) secure method to check if tag is genuine
						if ((response != null) && (response.length >= 2)) {
							byte[] packResponse = Arrays.copyOf(response, 2);
							if (!(pack[0] == packResponse[0] && pack[1] == packResponse[1])) {
								Log.d(TAG, "Tag could not be authenticated:\n" + packResponse.toString() + "≠" + pack.toString());
								//Toast.makeText(ctx, "Tag could not be authenticated:\n" + packResponse.toString() + "≠" + pack.toString(), Toast.LENGTH_LONG).show();
							}
						}
					//}catch(TagLostException e){
					}catch(Exception e){
						log.d(TAG, e.getMessage());
						e.printStackTrace();
					}

					// Get Page 2Ah
					response = nfca.transceive(new byte[] {
							(byte) 0x30, // READ
							(byte) 0x2A  // page address
					});
					// configure tag as write-protected with unlimited authentication tries
					if ((response != null) && (response.length >= 16)) {    // read always returns 4 pages
						boolean prot = false;                               // false = PWD_AUTH for write only, true = PWD_AUTH for read and write
						int authlim = 0;                                    // 0 = unlimited tries
						nfca.transceive(new byte[] {
								(byte) 0xA2, // WRITE
								(byte) 0x2A, // page address
								(byte) ((response[0] & 0x078) | (prot ? 0x080 : 0x000) | (authlim & 0x007)),    // set ACCESS byte according to our settings
								0, 0, 0                                                                         // fill rest as zeros as stated in datasheet (RFUI must be set as 0b)
						});
					}
					// Get page 29h
					response = nfca.transceive(new byte[] {
							(byte) 0x30, // READ
							(byte) 0x29  // page address
					});
					// Configure tag to protect entire storage (page 0 and above)
					if ((response != null) && (response.length >= 16)) {  // read always returns 4 pages
						int auth0 = 0;                                    // first page to be protected
						nfca.transceive(new byte[] {
								(byte) 0xA2, // WRITE
								(byte) 0x29, // page address
								response[0], 0, response[2],              // Keep old mirror values and write 0 in RFUI byte as stated in datasheet
								(byte) (auth0 & 0x0ff)
						});
					}

					// Send PACK and PWD
					// set PACK:
					nfca.transceive(new byte[] {
							(byte)0xA2,
							(byte)0x2C,
							pack[0], pack[1], 0, 0  // Write PACK into first 2 Bytes and 0 in RFUI bytes
					});
					// set PWD:
					nfca.transceive(new byte[] {
							(byte)0xA2,
							(byte)0x2B,
							pwd[0], pwd[1], pwd[2], pwd[3] // Write all 4 PWD bytes into Page 43
					});

					// Generate NdefMessage to be written onto the tag
					NdefMessage msg = null;
					try {
						NdefRecord r1 = NdefRecord.createMime("text/plain", message.getBytes("UTF-8"));
						NdefRecord r2 = NdefRecord.createApplicationRecord("com.example.alex.nfcapppcekunde");
						msg = new NdefMessage(r1, r2);
						
						Log.d(TAG, "Message saved");
					} catch (UnsupportedEncodingException e) {
						Log.d(TAG, "Error:");
						e.printStackTrace();
						
					}

					byte[] ndefMessage = msg.toByteArray();

					nfca.transceive(new byte[] {
							(byte)0xA2, // WRITE
							(byte)3,    // block address
							(byte)0xE1, (byte)0x10, (byte)0x12, (byte)0x00
					});

					// wrap into TLV structure
					byte[] tlvEncodedData = null;

					tlvEncodedData = new byte[ndefMessage.length + 3];
					tlvEncodedData[0] = (byte)0x03;  // NDEF TLV tag
					tlvEncodedData[1] = (byte)(ndefMessage.length & 0x0FF);  // NDEF TLV length (1 byte)
					System.arraycopy(ndefMessage, 0, tlvEncodedData, 2, ndefMessage.length);
					tlvEncodedData[2 + ndefMessage.length] = (byte)0xFE;  // Terminator TLV tag

					// fill up with zeros to block boundary:
					tlvEncodedData = Arrays.copyOf(tlvEncodedData, (tlvEncodedData.length / 4 + 1) * 4);
					for (int i = 0; i < tlvEncodedData.length; i += 4) {
						byte[] command = new byte[] {
								(byte)0xA2, // WRITE
								(byte)((4 + i / 4) & 0x0FF), // block address
								0, 0, 0, 0
						};
						System.arraycopy(tlvEncodedData, i, command, 2, 4);
						try {
							response = nfca.transceive(command);
							Log.d(TAG, "Response:");
							Log.d(TAG, response);
							
						} catch (IOException e) {
							Log.d(TAG, "Error:" + e.getMessage());
							e.printStackTrace();
						}
					}
					runOnUiThread(new Runnable() {
						@Override
						public void run() {
							//UI related things, not important for NFC
							//btn.setImageResource(R.drawable.arrow_red);
							//tv.setText("");
						}
					});
					curAction = "handle";
					
					read();
					
					try {
						nfca.close();
						Log.d(TAG, "NFC Closed");
					} catch (IOException e) {
						Log.d(TAG, "Error: " + e.getMessage());
						e.printStackTrace();
					}

				} catch (IOException e) {
					//Trying to catch any ioexception that may be thrown
					Log.d(TAG, "Error: " + e.getMessage());
					e.printStackTrace();
				} catch (Exception e) {
					Log.d(TAG, "Error: " + e.getMessage());
					//Trying to catch any exception that may be thrown
					e.printStackTrace();
				}

			}
		})).start();
	}
	
	private void read(){
		byte[] response;

		//Read page 41 on NTAG213, will be different for other tags
		response = mifare.transceive(new byte[] {
				(byte) 0x30, // READ
				41           // page address
		});
		// Authenticate with the tag first
		// only if the Auth0 byte is not 0xFF,
		// which is the default value meaning unprotected
		if(response[3] != (byte)0xFF) {
			try {
				response = mifare.transceive(new byte[]{
						(byte) 0x1B, // PWD_AUTH
						pwd[0], pwd[1], pwd[2], pwd[3]
				});
				
				Log.d(TAG, "Read Response:");
				Log.d(TAG, response);
				
				// Check if PACK is matching expected PACK
				// This is a (not that) secure method to check if tag is genuine
				if ((response != null) && (response.length >= 2)) {
					final byte[] packResponse = Arrays.copyOf(response, 2);
					if (!(pack[0] == packResponse[0] && pack[1] == packResponse[1])) {runOnUiThread(new Runnable() {
						@Override
						public void run() {
							//Toast.makeText(ctx, "Tag could not be authenticated:\n" + packResponse.toString() + "≠" + pack.toString(), Toast.LENGTH_LONG).show();
							Log.d(TAG, "Tag could not be authenticated:\n" + packResponse.toString() + "≠" + pack.toString());
						}
					});
					}else{
						runOnUiThread(new Runnable() {
							@Override
							public void run() {
								//Toast.makeText(ctx, "Tag successfully authenticated!", Toast.LENGTH_SHORT).show();
								Log.d(TAG, "Tag could not be authenticated:\n" + packResponse.toString() + "≠" + pack.toString());
							}
						});
					}
				}
			//} catch (TagLostException e) {
			} catch (Exception e) {
				Log.d(TAG, "Error: " + e.getMessage());
				e.printStackTrace();
				
			}
		}else{
			// Protect tag with your password in case
			// it's not protected yet

			// Get Page 2Ah
			response = mifare.transceive(new byte[] {
					(byte) 0x30, // READ
					(byte) 0x2A  // page address
			});
			// configure tag as write-protected with unlimited authentication tries
			if ((response != null) && (response.length >= 16)) {    // read always returns 4 pages
				boolean prot = false;                               // false = PWD_AUTH for write only, true = PWD_AUTH for read and write
				int authlim = 0;                                    // 0 = unlimited tries
				mifare.transceive(new byte[] {
						(byte) 0xA2, // WRITE
						(byte) 0x2A, // page address
						(byte) ((response[0] & 0x078) | (prot ? 0x080 : 0x000) | (authlim & 0x007)),    // set ACCESS byte according to our settings
						0, 0, 0                                                                         // fill rest as zeros as stated in datasheet (RFUI must be set as 0b)
				});
			}
			// Get page 29h
			response = mifare.transceive(new byte[] {
					(byte) 0x30, // READ
					(byte) 0x29  // page address
			});
			
			Log.d(TAG, "Response: ");
			Log.d(TAG, response);
			
			// Configure tag to protect entire storage (page 0 and above)
			if ((response != null) && (response.length >= 16)) {  // read always returns 4 pages
				int auth0 = 0;                                    // first page to be protected
				mifare.transceive(new byte[] {
						(byte) 0xA2, // WRITE
						(byte) 0x29, // page address
						response[0], 0, response[2],              // Keep old mirror values and write 0 in RFUI byte as stated in datasheet
						(byte) (auth0 & 0x0ff)
				});
			}

			// Send PACK and PWD
			// set PACK:
			mifare.transceive(new byte[] {
					(byte)0xA2,
					(byte)0x2C,
					pack[0], pack[1], 0, 0  // Write PACK into first 2 Bytes and 0 in RFUI bytes
			});
			// set PWD:
			mifare.transceive(new byte[] {
					(byte)0xA2,
					(byte)0x2B,
					pwd[0], pwd[1], pwd[2], pwd[3] // Write all 4 PWD bytes into Page 43
			});
		}
	}
}
