# User usage

## Using Psi

### Register to the transport

Login to your XMPP account normally, like you would do if the transport
did not exist at all.

![Psi connected to standard XMPP account](user_usage_psi_1.png)

Open the service discovery tool:

![Psi opening the service discovery window](user_usage_psi_2.png)

Find the transport and start the registration procedure on it:

![Registering the transport in Psi](user_usage_psi_3.png)

Copy the URL that is displayed in the window and open it in a webbrowser.

![Psi transport registration windows](user_usage_psi_4.png)

Follow the authorization procedure on Google's side.

You will obtain a code:

![The code](user_usage_psi_5.png)

Copy it into the registration window and validate:

![Psi transport registration window with the code](user_usage_psi_6.png)

The transport is connected. You should see your contacts in the roster,
and get invitations to MUCs when there's activity in them.

### Getting contact and conference information

You can get information about your hangout contacts and your hangouts
conferences in the service discovery window:

![Psi with all the information](user_usage_psi_7.png)

### Setting an alias to a conference id

By default, conference have their Hangout identifier as JIDs. This is
not very practical. The transport allows you to set alias to them.

Go to the service discovery, find your conference and execute a command:

![Setting a conference alias](user_usage_psi_8.png)

The only command available is the one to set an alias:

![Setting a conference alias](user_usage_psi_9.png)

Choose an alias name and validate:

![Setting a conference alias](user_usage_psi_10.png)

The conference will now be known as your alias in the roster, in the
list and in your window titles:

![Setting a conference alias](user_usage_psi_11.png)

## Using Pidgin

### Register to the transport
Login to your XMPP account normally, like you would do if the transport
did not exist at all.

Make sure the service discovery plugin is enabled:

![Installing the service discovery plugin](user_usage_pidgin_1.png)

Open the service discovery window:

![Opening the service discovery](user_usage_pidgin_2.png)

Browse the server node, find the transport, and register to it:

![Registereing to the transport](user_usage_pidgin_3.png)

Copy the URL that is displayed in the window and open it in a webbrowser.

![Pidgin transport registration](user_usage_pidgin_4.png)

Follow the authorization procedure on Google's side.

You will obtain a code:

![The code](user_usage_psi_5.png)

Copy it into the registration window and validate:

![Pidgin transport registration with the code](user_usage_pidgin_5.png)

Your contact will appear. To fetch their name and profile picture,
right click on them and click "Get info".

![Pidgin roster with contacts](user_usage_pidgin_6.png)

### Using conferences

Go to the room list:

![Pidgin roster with contacts](user_usage_pidgin_7.png)

Query the room list from the transport, by browsing `conf@[jid of the transport]`:

![Pidgin roster with contacts](user_usage_pidgin_8.png)

You'll get to the list of rooms:

![Pidgin roster with contacts](user_usage_pidgin_9.png)

There, you can open them and add them as contacts (then you won't need
to go through this process every time you want to talk there).

You can't add aliases to conversations in Pidgin. However, if you set
them in another client, they will be taken into account in Pidgin too.
