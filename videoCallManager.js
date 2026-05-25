// VideoCallManager.js
class VideoCallManager {
  constructor(socket, currentUser) {
    this.socket = socket;
    this.currentUser = currentUser;
    this.peerConnection = null;
    this.localStream = null;
    this.remoteStream = null;
    this.isInCall = false;
    this.currentCallWith = null;
    
    this.configuration = {
      iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' },
        { urls: 'stun:stun2.l.google.com:19302' }
      ]
    };
  }

  async initLocalStream() {
    try {
      this.localStream = await navigator.mediaDevices.getUserMedia({
        video: true,
        audio: true
      });
      return true;
    } catch (error) {
      console.error('Error accessing media devices:', error);
      throw error;
    }
  }

  setupVideoElements() {
    const localVideo = document.getElementById('localVideo');
    const remoteVideo = document.getElementById('remoteVideo');
    
    if (localVideo && this.localStream) {
      localVideo.srcObject = this.localStream;
    }
  }

  async startCall(targetUserId, targetUserName) {
    if (!this.localStream) {
      await this.initLocalStream();
    }

    this.currentCallWith = { id: targetUserId, name: targetUserName };
    
    this.peerConnection = new RTCPeerConnection(this.configuration);
    
    // Add local stream tracks
    this.localStream.getTracks().forEach(track => {
      this.peerConnection.addTrack(track, this.localStream);
    });

    // Handle remote stream
    this.peerConnection.ontrack = (event) => {
      this.remoteStream = event.streams[0];
      const remoteVideo = document.getElementById('remoteVideo');
      if (remoteVideo) {
        remoteVideo.srcObject = this.remoteStream;
      }
    };

    // Handle ICE candidates
    this.peerConnection.onicecandidate = (event) => {
      if (event.candidate) {
        this.socket.emit('call-user', {
          to: targetUserId,
          from: this.currentUser.id,
          signalData: event.candidate
        });
      }
    };

    // Create offer
    const offer = await this.peerConnection.createOffer();
    await this.peerConnection.setLocalDescription(offer);

    this.socket.emit('call-user', {
      to: targetUserId,
      from: this.currentUser.id,
      signalData: offer
    });

    this.isInCall = true;
    this.showCallUI(true);
  }

  async acceptCall(fromUserId, signal) {
    if (!this.localStream) {
      await this.initLocalStream();
    }

    this.peerConnection = new RTCPeerConnection(this.configuration);
    
    this.localStream.getTracks().forEach(track => {
      this.peerConnection.addTrack(track, this.localStream);
    });

    this.peerConnection.ontrack = (event) => {
      this.remoteStream = event.streams[0];
      const remoteVideo = document.getElementById('remoteVideo');
      if (remoteVideo) {
        remoteVideo.srcObject = this.remoteStream;
      }
    };

    this.peerConnection.onicecandidate = (event) => {
      if (event.candidate) {
        this.socket.emit('accept-call', {
          to: fromUserId,
          signal: event.candidate
        });
      }
    };

    await this.peerConnection.setRemoteDescription(signal);
    const answer = await this.peerConnection.createAnswer();
    await this.peerConnection.setLocalDescription(answer);

    this.socket.emit('accept-call', {
      to: fromUserId,
      signal: answer
    });

    this.isInCall = true;
    this.showCallUI(true);
  }

  async handleRemoteSignal(signal) {
    if (!this.peerConnection) return;
    
    if (signal.type === 'offer') {
      await this.peerConnection.setRemoteDescription(signal);
      const answer = await this.peerConnection.createAnswer();
      await this.peerConnection.setLocalDescription(answer);
      this.socket.emit('accept-call', {
        to: this.currentCallWith?.id,
        signal: answer
      });
    } else if (signal.type === 'answer') {
      await this.peerConnection.setRemoteDescription(signal);
    } else if (signal.candidate) {
      await this.peerConnection.addIceCandidate(signal);
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
    this.currentCallWith = null;
    this.showCallUI(false);
    
    // Clear video elements
    const localVideo = document.getElementById('localVideo');
    const remoteVideo = document.getElementById('remoteVideo');
    if (localVideo) localVideo.srcObject = null;
    if (remoteVideo) remoteVideo.srcObject = null;
  }

  showCallUI(inCall) {
    const callModal = document.getElementById('callModal');
    const videoCallBtn = document.getElementById('videoCallBtn');
    const endCallBtn = document.getElementById('endCallBtn');
    
    if (callModal) {
      callModal.style.display = inCall ? 'flex' : 'none';
    }
    
    if (videoCallBtn) {
      videoCallBtn.style.display = inCall ? 'none' : 'inline-block';
    }
    
    if (endCallBtn) {
      endCallBtn.style.display = inCall ? 'inline-block' : 'none';
    }
  }
}