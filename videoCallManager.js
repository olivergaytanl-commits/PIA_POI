class VideoCallManager {
    constructor(socket, currentUser) {
        this.socket = socket;
        this.currentUser = currentUser;
        this.peerConnection = null;
        this.localStream = null;
        this.remoteStream = null;
        this.isInCall = false;
        this.currentCallWith = null;
        this.iceCandidateQueue = [];
        
        this.configuration = {
            iceServers: [
                { urls: 'stun:stun.relay.metered.ca:80' },
                {
                    urls: 'turn:global.relay.metered.ca:80',
                    username: '9f4e271e08ea6740306b75a9',
                    credential: 'TYOXGgRZdHOOdwu4'
                },
                {
                    urls: 'turn:global.relay.metered.ca:80?transport=tcp',
                    username: '9f4e271e08ea6740306b75a9',
                    credential: 'TYOXGgRZdHOOdwu4'
                },
                {
                    urls: 'turn:global.relay.metered.ca:443',
                    username: '9f4e271e08ea6740306b75a9',
                    credential: 'TYOXGgRZdHOOdwu4'
                },
                {
                    urls: 'turns:global.relay.metered.ca:443?transport=tcp',
                    username: '9f4e271e08ea6740306b75a9',
                    credential: 'TYOXGgRZdHOOdwu4'
                }
            ]
        };
    }

    async initLocalStream() {
        try {
            this.localStream = await navigator.mediaDevices.getUserMedia({
                video: true,
                audio: true
            });
            const localVideo = document.getElementById('localVideo');
            if (localVideo) localVideo.srcObject = this.localStream;
            return true;
        } catch (error) {
            console.error('❌ Error al acceder a dispositivos:', error);
            alert('No se pudo acceder a la cámara/micrófono. Verifica los permisos.');
            return false;
        }
    }

    async startCall(targetUserId, targetUserName) {
        if (!this.localStream) {
            const success = await this.initLocalStream();
            if (!success) return;
        }

        this.currentCallWith = { id: targetUserId, name: targetUserName };
        this.iceCandidateQueue = [];
        this.peerConnection = new RTCPeerConnection(this.configuration);

        this.localStream.getTracks().forEach(track => {
            this.peerConnection.addTrack(track, this.localStream);
        });

        this.peerConnection.ontrack = (event) => {
            this.remoteStream = event.streams[0];
            const remoteVideo = document.getElementById('remoteVideo');
            if (remoteVideo) remoteVideo.srcObject = this.remoteStream;
        };

        this.peerConnection.onicecandidate = (event) => {
            if (event.candidate) {
                this.socket.emit('ice-candidate-caller', {
                    to: targetUserId,
                    candidate: event.candidate
                });
            }
        };

        this.peerConnection.onconnectionstatechange = () => {
            console.log(`🔌 Estado conexión: ${this.peerConnection.connectionState}`);
            if (this.peerConnection.connectionState === 'failed') {
                console.error('❌ Conexión fallida');
                this.endCall();
            }
        };

        try {
            const offer = await this.peerConnection.createOffer();
            await this.peerConnection.setLocalDescription(offer);

            this.socket.emit('call-user', {
                to: targetUserId,
                from: this.currentUser.id,
                signalData: offer
            });

            this.isInCall = true;
            this.showCallUI(true);
        } catch (error) {
            console.error('❌ Error al iniciar llamada:', error);
        }
    }

    async acceptCall(fromUserId, signal) {
        if (!this.localStream) {
            const success = await this.initLocalStream();
            if (!success) return;
        }

        this.currentCallWith = { id: fromUserId, name: '' };
        this.iceCandidateQueue = [];
        this.peerConnection = new RTCPeerConnection(this.configuration);

        this.localStream.getTracks().forEach(track => {
            this.peerConnection.addTrack(track, this.localStream);
        });

        this.peerConnection.ontrack = (event) => {
            this.remoteStream = event.streams[0];
            const remoteVideo = document.getElementById('remoteVideo');
            if (remoteVideo) remoteVideo.srcObject = this.remoteStream;
        };

        this.peerConnection.onicecandidate = (event) => {
            if (event.candidate) {
                this.socket.emit('ice-candidate-callee', {
                    to: fromUserId,
                    candidate: event.candidate
                });
            }
        };

        this.peerConnection.onconnectionstatechange = () => {
            console.log(`🔌 Estado conexión: ${this.peerConnection.connectionState}`);
            if (this.peerConnection.connectionState === 'failed') {
                this.endCall();
            }
        };

        try {
            await this.peerConnection.setRemoteDescription(signal);

            // Vaciar cola de candidatos que llegaron antes del remote description
            for (const c of this.iceCandidateQueue) {
                await this.peerConnection.addIceCandidate(c);
            }
            this.iceCandidateQueue = [];

            const answer = await this.peerConnection.createAnswer();
            await this.peerConnection.setLocalDescription(answer);

            this.socket.emit('accept-call', { to: fromUserId, signal: answer });
            this.isInCall = true;
            this.showCallUI(true);
        } catch (error) {
            console.error('❌ Error al aceptar llamada:', error);
        }
    }

    async handleRemoteSignal(signal) {
        if (!this.peerConnection) return;

        try {
            if (signal.type === 'answer') {
                await this.peerConnection.setRemoteDescription(signal);

                // Vaciar cola
                for (const c of this.iceCandidateQueue) {
                    await this.peerConnection.addIceCandidate(c);
                }
                this.iceCandidateQueue = [];

            } else if (signal.candidate) {
                if (!this.peerConnection.remoteDescription) {
                    this.iceCandidateQueue.push(signal);
                } else {
                    await this.peerConnection.addIceCandidate(signal);
                }
            }
        } catch (error) {
            console.error('❌ Error manejando señal:', error);
        }
    }

    endCall() {
        if (this.peerConnection) {
            this.peerConnection.close();
            this.peerConnection = null;
        }

        if (this.localStream) {
            this.localStream.getTracks().forEach(track => track.stop());
            this.localStream = null;
        }

        this.remoteStream = null;
        this.isInCall = false;
        this.iceCandidateQueue = [];

        if (this.currentCallWith) {
            this.socket.emit('hangup', { to: this.currentCallWith.id });
            this.currentCallWith = null;
        }

        this.showCallUI(false);

        const localVideo = document.getElementById('localVideo');
        const remoteVideo = document.getElementById('remoteVideo');
        if (localVideo) localVideo.srcObject = null;
        if (remoteVideo) remoteVideo.srcObject = null;
    }

    showCallUI(inCall) {
        const callModal = document.getElementById('videoCallModal');
        if (callModal) callModal.style.display = inCall ? 'flex' : 'none';
        document.body.style.overflow = inCall ? 'hidden' : '';
    }
}