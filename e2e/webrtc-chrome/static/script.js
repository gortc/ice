var peerConnection;
const peerConnectionConfig = {};
const dataChannelOptions = {
    ordered: false, // do not guarantee order
};

function pageReady() {
    fetch("/config").then(res => res.json()).then(function (myJSON) {
        serverConnection = new WebSocket(myJSON.signaling);
        serverConnection.onmessage = gotMessageFromServer;

        if (myJSON.controlling) {
            start(true);
        } else {
            serverConnection.onopen = () => {
                fetch("/initialized", {
                    method: "post"
                }).catch((reason) => {
                    console.log("failed to init notify", reason)
                })
            }
        }
    });
}

function receiveChannelCallback(event) {
    console.log('received data channel');
    const receiveChannel = event.channel;
    receiveChannel.onmessage = (event) => {
        console.log("dataChannel message:", event.data);
        fetch("/success").then(function () {
            console.log("success");
        })
    };
    receiveChannel.onopen = () => {
        receiveChannel.send("hello [from controlled]");
    };
    receiveChannel.onclose = () => {
        console.log("dataChannel closed");
    };
}

function start(isCaller) {
    peerConnection = new RTCPeerConnection(peerConnectionConfig);
    peerConnection.onicecandidate = gotIceCandidate;
    peerConnection.ondatachannel = receiveChannelCallback;
    peerConnection.onconnectionstatechange = function(event) {
        console.log("connection state", peerConnection.connectionState);
        switch(peerConnection.connectionState) {
            case "connected":
                // The connection has become fully connected
                break;
            case "disconnected":
            case "failed":
                // One or more transports has terminated unexpectedly or in an error
                break;
            case "closed":
                // The connection has been closed
                break;
        }
    };
    if(isCaller) {
        const dataChannel = peerConnection.createDataChannel("matrix", dataChannelOptions);
        dataChannel.onerror = (error) => {
            console.log("dataChannel error:", error);
        };
        dataChannel.onmessage = (event) => {
            console.log("dataChannel message:", event.data);
            fetch("/success").then(function () {
                console.log("success");
            })
        };
        dataChannel.onopen = () => {
            console.log("dataChannel opened");
            dataChannel.send("hello [from caller]");
        };
        dataChannel.onclose = () => {
            console.log("dataChannel closed");
        };
        peerConnection.createOffer().then(gotDescription).catch(createOfferError);
    }
}

function gotDescription(description) {
    console.log('got description');
    peerConnection.setLocalDescription(description).then(function () {
        // serverConnection.send(JSON.stringify({'sdp': description}))
        // TODO: Use with trickle.
    }).catch(function () {
        console.log('set description error')
    });
}

function gotIceCandidate(event) {
    if(event.candidate != null) {
        serverConnection.send(JSON.stringify({'ice': event.candidate}));
    } else {
        console.log("local description", peerConnection.localDescription);
        serverConnection.send(JSON.stringify({'sdp': peerConnection.localDescription}));
    }
}

function createOfferError(error) {
    console.log(error);
}

function gotMessageFromServer(message) {
    if(!peerConnection) start(false);
    const signal = JSON.parse(message.data);
    if(signal.success) {
        // TODO: Remove when data-channels ready.
        console.log("forced success");
        fetch("/success").then(function () {
            console.log("success");
        })
    }
    if(signal.sdp) {
        console.log("got remote description", signal.sdp);
        const d = new RTCSessionDescription(signal.sdp);
        console.log("got remote description", d);
        peerConnection.setRemoteDescription(d).then(function() {
            console.log("set remote description");
            if(signal.sdp.type === 'offer') {
                peerConnection.createAnswer().then(gotDescription).catch(function (err) {
                    console.log(err);
                });
            } else {
                serverConnection.send(JSON.stringify({'signal': "gotDescription"}));
            }
        }).catch(function (reason) {
            console.log("failed to set remote description:", reason)
        });
    } else if(signal.ice) {
        peerConnection.addIceCandidate(new RTCIceCandidate(signal.ice)).then(function () {
            console.log("ice candidate added")
        });
    }
}

pageReady();