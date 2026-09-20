<!doctype html>
<html lang="sw">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">

<title>Tanzania Dating ❤️</title>

<style>

*{
  box-sizing:border-box;
}

body{
  margin:0;
  font-family:Arial,sans-serif;
  background:#fff5f8;
  color:#24131b;
}

header{
  background:linear-gradient(135deg,#ff174f,#e60046);
  color:white;
  padding:14px;
  position:sticky;
  top:0;
  z-index:100;
  box-shadow:0 2px 10px #0002;
}

.header-row{
  max-width:900px;
  margin:auto;
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:10px;
}

.logo{
  font-size:20px;
  font-weight:bold;
}

.container{
  max-width:900px;
  margin:auto;
  padding:15px;
}

.card{
  background:white;
  border-radius:18px;
  padding:18px;
  margin-bottom:15px;
  box-shadow:0 4px 15px #00000012;
}

.auth-box{
  max-width:450px;
  margin:35px auto;
}

.auth-title{
  text-align:center;
  font-size:30px;
  margin-bottom:5px;
}

.auth-sub{
  text-align:center;
  color:#777;
  margin-bottom:25px;
}

input,
select,
textarea{
  width:100%;
  padding:14px;
  border:1px solid #ddd;
  border-radius:12px;
  margin-top:7px;
  margin-bottom:13px;
  font-size:16px;
  outline:none;
  background:white;
}

input:focus,
select:focus,
textarea:focus{
  border-color:#ff174f;
}

textarea{
  min-height:100px;
  resize:vertical;
}

button{
  border:0;
  border-radius:12px;
  padding:12px 15px;
  background:#ff174f;
  color:white;
  font-size:15px;
  font-weight:bold;
  cursor:pointer;
}

button:hover{
  opacity:.92;
}

button.secondary{
  background:#eee;
  color:#333;
}

button.green{
  background:#19a974;
}

button.dark{
  background:#333;
}

button.danger{
  background:#d60035;
}

button.blue{
  background:#1976d2;
}

.hidden{
  display:none!important;
}

.center{
  text-align:center;
}

.muted{
  color:#777;
}

.small{
  font-size:13px;
}

.tabs{
  display:flex;
  gap:7px;
  overflow-x:auto;
  padding:12px 0;
  position:sticky;
  top:59px;
  background:#fff5f8;
  z-index:50;
}

.tabs button{
  white-space:nowrap;
  padding:10px 13px;
}

.badge{
  display:inline-flex;
  min-width:20px;
  height:20px;
  align-items:center;
  justify-content:center;
  background:white;
  color:#e60046;
  border-radius:20px;
  font-size:11px;
  margin-left:4px;
}

.profile-card{
  display:flex;
  gap:15px;
  align-items:flex-start;
}

.profile-photo{
  width:105px;
  height:105px;
  border-radius:50%;
  object-fit:cover;
  background:#eee;
  flex-shrink:0;
}

.profile-info{
  flex:1;
}

.profile-name{
  font-size:20px;
  font-weight:bold;
}

.actions{
  display:flex;
  gap:8px;
  flex-wrap:wrap;
  margin-top:14px;
}

.actions button{
  flex:1;
  min-width:110px;
}

.distance{
  display:inline-block;
  background:#fff0f4;
  color:#e60046;
  padding:5px 9px;
  border-radius:20px;
  font-size:12px;
  margin-top:5px;
}

.nearby-box{
  background:linear-gradient(135deg,#fff,#fff0f4);
  border:1px solid #ffd0dc;
}

.location-status{
  padding:12px;
  border-radius:12px;
  background:#f5f5f5;
  margin:10px 0;
}

.chat-list{
  display:flex;
  flex-direction:column;
}

.chat-item{
  display:flex;
  align-items:center;
  gap:12px;
  padding:13px 5px;
  border-bottom:1px solid #eee;
  cursor:pointer;
}

.chat-item:last-child{
  border-bottom:0;
}

.chat-avatar{
  width:55px;
  height:55px;
  border-radius:50%;
  object-fit:cover;
  background:#eee;
}

.chat-info{
  flex:1;
  min-width:0;
}

.chat-name{
  font-weight:bold;
  margin-bottom:5px;
}

.last-message{
  color:#777;
  white-space:nowrap;
  overflow:hidden;
  text-overflow:ellipsis;
}

.chat-time{
  font-size:11px;
  color:#999;
}

.chat-window{
  background:white;
  border-radius:18px;
  overflow:hidden;
  box-shadow:0 4px 15px #00000012;
}

.chat-header{
  display:flex;
  align-items:center;
  gap:10px;
  padding:13px;
  background:#ff174f;
  color:white;
}

.chat-header img{
  width:45px;
  height:45px;
  border-radius:50%;
  object-fit:cover;
  background:white;
}

.chat-header-info{
  flex:1;
}

.chat-messages{
  height:55vh;
  min-height:300px;
  max-height:600px;
  overflow-y:auto;
  padding:15px;
  background:#fff8fa;
}

.message-row{
  display:flex;
  margin-bottom:9px;
}

.message-row.mine{
  justify-content:flex-end;
}

.message{
  max-width:78%;
  padding:10px 13px;
  border-radius:15px;
  background:#eee;
  word-wrap:break-word;
}

.message-row.mine .message{
  background:#ff174f;
  color:white;
  border-bottom-right-radius:4px;
}

.message-row:not(.mine) .message{
  border-bottom-left-radius:4px;
}

.message-time{
  display:block;
  font-size:10px;
  opacity:.65;
  margin-top:4px;
}

.chat-input{
  display:flex;
  gap:8px;
  padding:10px;
  background:white;
  border-top:1px solid #eee;
}

.chat-input input{
  margin:0;
  flex:1;
}

.chat-input button{
  width:75px;
}

.notification{
  padding:13px;
  border-bottom:1px solid #eee;
}

.notification.unread{
  background:#fff0f4;
}

.notification-title{
  font-weight:bold;
}

.notification-time{
  color:#999;
  font-size:11px;
}

.my-profile{
  text-align:center;
}

.my-profile img{
  width:140px;
  height:140px;
  border-radius:50%;
  object-fit:cover;
  background:#eee;
}

.empty{
  text-align:center;
  padding:35px 15px;
  color:#777;
}

.loading{
  text-align:center;
  padding:30px;
  color:#777;
}

.toast{
  position:fixed;
  bottom:20px;
  left:50%;
  transform:translateX(-50%);
  background:#222;
  color:white;
  padding:12px 18px;
  border-radius:12px;
  z-index:9999;
  display:none;
  max-width:90%;
  text-align:center;
}

.nearby-icon{
  font-size:45px;
  text-align:center;
  margin-bottom:10px;
}

@media(max-width:600px){

  .container{
    padding:10px;
  }

  .profile-card{
    flex-direction:column;
    align-items:center;
    text-align:center;
  }

  .profile-info{
    width:100%;
  }

  .profile-photo{
    width:130px;
    height:130px;
  }

  .actions button{
    min-width:100px;
  }

  .logo{
    font-size:17px;
  }

  .chat-messages{
    min-height:300px;
  }
}

</style>
</head>

<body>


<!-- =====================================================
     HEADER
====================================================== -->

<header id="mainHeader" class="hidden">

  <div class="header-row">

    <div class="logo">
      Tanzania Dating ❤️
    </div>

    <div>

      <button onclick="showPage('notifications')">
        🔔
        <span id="notifyBadge" class="badge hidden">0</span>
      </button>

      <button
        class="secondary"
        onclick="logout()">
        Toka
      </button>

    </
