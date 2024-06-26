const express = require("express");
const dotenv = require("dotenv");
const dbConnect= require('./dbConnect'); 
const authRouter = require('./routers/authRouter');
const postsRouter = require('./routers/postsRouter');
const userRouter = require('./routers/userRouter');
const morgan = require('morgan');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const cloudinary = require('cloudinary').v2;

dotenv.config("./.env"); 


cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET 
})
 
const app = express(); 

//middlewares
app.use(express.json({limit:'10mb'}));
app.use(morgan('common'));
app.use(cookieParser());
app.use(cors({
    credentials: true,
    origin: 'https://social-media-client-one-pearl.vercel.app'
}));

app.use('/auth',authRouter);
app.use('/posts',postsRouter);

app.use('/user',userRouter);
app.get('/', (req, res) => {
    res.status(200).send('OK from Server');
})

const PORT = process.env.PORT || 4001;

dbConnect();//Error is that server crashes in nodemon
app.listen(PORT, ()=>{
    console.log(`listening on port: ${PORT}`);
});