const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const archiver = require('archiver');

const app = express();
const PORT = process.env.PORT || 3000;

// ----- КОНФИГ -----
const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

const USERS_FILE = path.join(DATA_DIR, 'users.json');
const CATEGORIES_FILE = path.join(DATA_DIR, 'categories.json');
const THREADS_FILE = path.join(DATA_DIR, 'threads.json');
const POSTS_FILE = path.join(DATA_DIR, 'posts.json');
const RESOURCES_FILE = path.join(DATA_DIR, 'resources.json');
const MESSAGES_FILE = path.join(DATA_DIR, 'messages.json');
const SUBSCRIPTIONS_FILE = path.join(DATA_DIR, 'subscriptions.json');
const LIKES_FILE = path.join(DATA_DIR, 'likes.json');
const NOTIFICATIONS_FILE = path.join(DATA_DIR, 'notifications.json');
const STYLES_FILE = path.join(DATA_DIR, 'styles.json');

function initFile(f, d = []) {
    if (!fs.existsSync(f)) fs.writeFileSync(f, JSON.stringify(d, null, 2));
}
initFile(USERS_FILE);
initFile(CATEGORIES_FILE, [
    { id: 'samp', name: 'SA:MP', subforums: ['Моды', 'Скрипты', 'Плагины', 'Текстдравы', 'Маппинг', 'Остальное'] },
    { id: 'crmp', name: 'CR:MP', subforums: ['Моды', 'Скрипты', 'Плагины', 'Текстдравы', 'Маппинг', 'Остальное'] },
    { id: 'openmp', name: 'open.mp', subforums: ['Моды', 'Скрипты', 'Плагины', 'Текстдравы', 'Маппинг', 'Остальное'] },
    { id: 'xenforo', name: 'XenForo', subforums: ['Релизы', 'Стили', 'Русификаторы', 'Плагины', 'Готовые решения'] },
    { id: 'web', name: 'Web-разработка', subforums: ['PHP', 'HTML / CSS', 'Python', 'JavaScript', 'Дизайнерский уголок'] }
]);
initFile(THREADS_FILE);
initFile(POSTS_FILE);
initFile(RESOURCES_FILE);
initFile(MESSAGES_FILE);
initFile(SUBSCRIPTIONS_FILE);
initFile(LIKES_FILE);
initFile(NOTIFICATIONS_FILE);
initFile(STYLES_FILE, { primary: '#1877f2', secondary: '#f0f2f5' });

function readJSON(f) { return JSON.parse(fs.readFileSync(f, 'utf8')); }
function writeJSON(f, d) { fs.writeFileSync(f, JSON.stringify(d, null, 2)); }

function getUser(id) {
    const users = readJSON(USERS_FILE);
    return users.find(u => u.id === id);
}
function getUsername(id) { const u = getUser(id); return u ? u.username : 'Удалён'; }
function createNotification(userId, message, link = '') {
    const notifs = readJSON(NOTIFICATIONS_FILE);
    notifs.push({ id: Date.now().toString(), userId, message, link, read: false, createdAt: new Date().toISOString() });
    writeJSON(NOTIFICATIONS_FILE, notifs);
}

// ----- MIDDLEWARE -----
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: 'xenforo-like-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
}));
app.use(express.static(__dirname));

// Настройка multer (в память, потом архивируем)
const storage = multer.memoryStorage();
const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) cb(null, true);
        else cb(new Error('Только изображения'));
    }
});

// ----- ПРОВЕРКА ПРАВ -----
function isAuth(req, res, next) {
    if (req.session.userId) return next();
    res.status(401).json({ error: 'Не авторизован' });
}
function isAdmin(req, res, next) {
    const user = getUser(req.session.userId);
    if (user && (user.role === 'admin' || user.role === 'moderator')) return next();
    res.status(403).json({ error: 'Недостаточно прав' });
}

// ----- API -----

// Регистрация (Badr – админ)
app.post('/api/register', async (req, res) => {
    const { username, password, confirmPassword } = req.body;
    if (!username || !password || !confirmPassword) return res.status(400).json({ error: 'Заполните все поля' });
    if (password !== confirmPassword) return res.status(400).json({ error: 'Пароли не совпадают' });
    if (password.length < 6) return res.status(400).json({ error: 'Минимум 6 символов' });

    const users = readJSON(USERS_FILE);
    if (users.find(u => u.username === username)) return res.status(400).json({ error: 'Пользователь уже существует' });

    const hashed = await bcrypt.hash(password, 10);
    const role = (username === 'Badr') ? 'admin' : 'user';
    const newUser = {
        id: Date.now().toString(),
        username,
        password: hashed,
        registeredAt: new Date().toISOString(),
        role,
        avatar: `https://www.gravatar.com/avatar/${require('crypto').createHash('md5').update(username).digest('hex')}?d=identicon&s=100`
    };
    users.push(newUser);
    writeJSON(USERS_FILE, users);
    req.session.userId = newUser.id;
    req.session.username = username;
    res.json({ success: true, username });
});

// Вход
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const users = readJSON(USERS_FILE);
    const user = users.find(u => u.username === username);
    if (!user) return res.status(400).json({ error: 'Неверные данные' });
    if (!await bcrypt.compare(password, user.password)) return res.status(400).json({ error: 'Неверные данные' });
    req.session.userId = user.id;
    req.session.username = username;
    res.json({ success: true, username });
});

// Выход
app.get('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// Текущий пользователь
app.get('/api/me', (req, res) => {
    if (!req.session.userId) return res.json(null);
    const user = getUser(req.session.userId);
    if (!user) return res.json(null);
    res.json({ id: user.id, username: user.username, role: user.role, avatar: user.avatar });
});

// Категории с подфорумами
app.get('/api/categories', (req, res) => {
    const cats = readJSON(CATEGORIES_FILE);
    res.json(cats);
});

// Темы (список с пагинацией и фильтром по категории/подфоруму)
app.get('/api/threads', (req, res) => {
    const { category, subforum, page = 1, limit = 10 } = req.query;
    let threads = readJSON(THREADS_FILE);
    if (category) threads = threads.filter(t => t.categoryId === category);
    if (subforum) threads = threads.filter(t => t.subforum === subforum);
    threads.sort((a, b) => {
        if (a.pinned && !b.pinned) return -1;
        if (!a.pinned && b.pinned) return 1;
        return new Date(b.lastPostAt || b.createdAt) - new Date(a.lastPostAt || a.createdAt);
    });
    const total = threads.length;
    const start = (page - 1) * limit;
    const end = start + limit;
    const data = threads.slice(start, end).map(t => ({
        ...t,
        authorName: getUsername(t.authorId),
        lastPostAuthor: t.lastPostAuthorId ? getUsername(t.lastPostAuthorId) : null
    }));
    res.json({ threads: data, total, page: parseInt(page), limit: parseInt(limit) });
});

// Создание темы
app.post('/api/threads', isAuth, (req, res) => {
    const { title, content, categoryId, subforum } = req.body;
    if (!title || !content || !categoryId || !subforum) {
        return res.status(400).json({ error: 'Заполните все поля' });
    }
    const cats = readJSON(CATEGORIES_FILE);
    const cat = cats.find(c => c.id === categoryId);
    if (!cat || !cat.subforums.includes(subforum)) {
        return res.status(400).json({ error: 'Неверная категория или подфорум' });
    }
    const threads = readJSON(THREADS_FILE);
    const newThread = {
        id: Date.now().toString(),
        title,
        content,
        authorId: req.session.userId,
        categoryId,
        subforum,
        createdAt: new Date().toISOString(),
        lastPostAt: new Date().toISOString(),
        lastPostAuthorId: req.session.userId,
        replies: 0,
        views: 0,
        pinned: false,
        locked: false
    };
    threads.push(newThread);
    writeJSON(THREADS_FILE, threads);
    res.json({ success: true, thread: newThread });
});

// Получение одной темы + посты (с пагинацией)
app.get('/api/threads/:id', (req, res) => {
    const { page = 1, limit = 5 } = req.query;
    const threads = readJSON(THREADS_FILE);
    const thread = threads.find(t => t.id === req.params.id);
    if (!thread) return res.status(404).json({ error: 'Тема не найдена' });
    thread.views = (thread.views || 0) + 1;
    writeJSON(THREADS_FILE, threads);

    const posts = readJSON(POSTS_FILE);
    const threadPosts = posts.filter(p => p.threadId === thread.id).sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
    const total = threadPosts.length;
    const start = (page - 1) * limit;
    const end = start + limit;
    const pagePosts = threadPosts.slice(start, end).map(p => {
        const likes = readJSON(LIKES_FILE).filter(l => l.postId === p.id).length;
        const liked = req.session.userId ? readJSON(LIKES_FILE).some(l => l.postId === p.id && l.userId === req.session.userId) : false;
        return {
            ...p,
            authorName: getUsername(p.authorId),
            authorAvatar: getUser(p.authorId)?.avatar || 'https://www.gravatar.com/avatar/default?d=identicon&s=30',
            likes,
            liked
        };
    });
    let subscribed = false;
    if (req.session.userId) {
        const subs = readJSON(SUBSCRIPTIONS_FILE);
        subscribed = subs.some(s => s.userId === req.session.userId && s.threadId === thread.id);
    }
    res.json({
        thread: { ...thread, authorName: getUsername(thread.authorId) },
        posts: pagePosts,
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        subscribed
    });
});

// Редактирование темы (модератор)
app.put('/api/threads/:id', isAuth, isAdmin, (req, res) => {
    const { title, content, categoryId, pinned, locked } = req.body;
    const threads = readJSON(THREADS_FILE);
    const idx = threads.findIndex(t => t.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Тема не найдена' });
    const thread = threads[idx];
    if (title) thread.title = title;
    if (content) thread.content = content;
    if (categoryId) thread.categoryId = categoryId;
    if (pinned !== undefined) thread.pinned = pinned;
    if (locked !== undefined) thread.locked = locked;
    writeJSON(THREADS_FILE, threads);
    res.json({ success: true, thread });
});

// Удаление темы (админ)
app.delete('/api/threads/:id', isAuth, isAdmin, (req, res) => {
    let threads = readJSON(THREADS_FILE);
    threads = threads.filter(t => t.id !== req.params.id);
    writeJSON(THREADS_FILE, threads);
    let posts = readJSON(POSTS_FILE);
    posts = posts.filter(p => p.threadId !== req.params.id);
    writeJSON(POSTS_FILE, posts);
    res.json({ success: true });
});

// Добавление ответа
app.post('/api/posts', isAuth, (req, res) => {
    const { threadId, content } = req.body;
    if (!threadId || !content) return res.status(400).json({ error: 'Заполните все поля' });
    const threads = readJSON(THREADS_FILE);
    const thread = threads.find(t => t.id === threadId);
    if (!thread) return res.status(404).json({ error: 'Тема не найдена' });
    if (thread.locked) return res.status(403).json({ error: 'Тема закрыта' });

    const posts = readJSON(POSTS_FILE);
    const newPost = {
        id: Date.now().toString(),
        threadId,
        content,
        authorId: req.session.userId,
        createdAt: new Date().toISOString(),
        editedAt: null
    };
    posts.push(newPost);
    writeJSON(POSTS_FILE, posts);

    thread.replies += 1;
    thread.lastPostAt = new Date().toISOString();
    thread.lastPostAuthorId = req.session.userId;
    writeJSON(THREADS_FILE, threads);

    const subs = readJSON(SUBSCRIPTIONS_FILE);
    const subscribers = subs.filter(s => s.threadId === threadId && s.userId !== req.session.userId);
    for (const sub of subscribers) {
        createNotification(sub.userId, `Новый ответ в теме "${thread.title}"`, `/thread/${threadId}`);
    }
    res.json({ success: true, post: newPost });
});

// Редактирование поста
app.put('/api/posts/:id', isAuth, (req, res) => {
    const { content } = req.body;
    if (!content) return res.status(400).json({ error: 'Введите текст' });
    const posts = readJSON(POSTS_FILE);
    const idx = posts.findIndex(p => p.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Пост не найден' });
    const post = posts[idx];
    const user = getUser(req.session.userId);
    if (post.authorId !== req.session.userId && user.role !== 'admin' && user.role !== 'moderator') {
        return res.status(403).json({ error: 'Нет прав' });
    }
    post.content = content;
    post.editedAt = new Date().toISOString();
    writeJSON(POSTS_FILE, posts);
    res.json({ success: true, post });
});

// Удаление поста (модератор)
app.delete('/api/posts/:id', isAuth, isAdmin, (req, res) => {
    let posts = readJSON(POSTS_FILE);
    const post = posts.find(p => p.id === req.params.id);
    if (!post) return res.status(404).json({ error: 'Пост не найден' });
    posts = posts.filter(p => p.id !== req.params.id);
    writeJSON(POSTS_FILE, posts);
    const threads = readJSON(THREADS_FILE);
    const thread = threads.find(t => t.id === post.threadId);
    if (thread) {
        thread.replies = Math.max(0, thread.replies - 1);
        writeJSON(THREADS_FILE, threads);
    }
    res.json({ success: true });
});

// Лайк
app.post('/api/like', isAuth, (req, res) => {
    const { postId } = req.body;
    if (!postId) return res.status(400).json({ error: 'Нет ID поста' });
    const likes = readJSON(LIKES_FILE);
    const existing = likes.find(l => l.postId === postId && l.userId === req.session.userId);
    if (existing) {
        const newLikes = likes.filter(l => l.id !== existing.id);
        writeJSON(LIKES_FILE, newLikes);
        return res.json({ success: true, action: 'unliked' });
    } else {
        const newLike = { id: Date.now().toString(), postId, userId: req.session.userId };
        likes.push(newLike);
        writeJSON(LIKES_FILE, likes);
        return res.json({ success: true, action: 'liked' });
    }
});

// Подписка
app.post('/api/subscribe', isAuth, (req, res) => {
    const { threadId } = req.body;
    if (!threadId) return res.status(400).json({ error: 'Нет ID темы' });
    const subs = readJSON(SUBSCRIPTIONS_FILE);
    const existing = subs.find(s => s.userId === req.session.userId && s.threadId === threadId);
    if (existing) {
        const newSubs = subs.filter(s => s.id !== existing.id);
        writeJSON(SUBSCRIPTIONS_FILE, newSubs);
        return res.json({ success: true, subscribed: false });
    } else {
        const newSub = { id: Date.now().toString(), userId: req.session.userId, threadId };
        subs.push(newSub);
        writeJSON(SUBSCRIPTIONS_FILE, subs);
        return res.json({ success: true, subscribed: true });
    }
});

// Уведомления
app.get('/api/notifications', isAuth, (req, res) => {
    const notifs = readJSON(NOTIFICATIONS_FILE);
    const userNotifs = notifs.filter(n => n.userId === req.session.userId).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    res.json(userNotifs);
});
app.put('/api/notifications/:id', isAuth, (req, res) => {
    const notifs = readJSON(NOTIFICATIONS_FILE);
    const n = notifs.find(n => n.id === req.params.id && n.userId === req.session.userId);
    if (n) { n.read = true; writeJSON(NOTIFICATIONS_FILE, notifs); res.json({ success: true }); }
    else res.status(404).json({ error: 'Не найдено' });
});

// Личные сообщения
app.get('/api/messages', isAuth, (req, res) => {
    const msgs = readJSON(MESSAGES_FILE);
    const userMsgs = msgs.filter(m => m.to === req.session.userId || m.from === req.session.userId)
        .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    const enriched = userMsgs.map(m => ({
        ...m,
        fromName: getUsername(m.from),
        toName: getUsername(m.to)
    }));
    res.json(enriched);
});
app.post('/api/messages', isAuth, (req, res) => {
    const { to, subject, content } = req.body;
    if (!to || !subject || !content) return res.status(400).json({ error: 'Заполните все поля' });
    const users = readJSON(USERS_FILE);
    const recipient = users.find(u => u.username === to);
    if (!recipient) return res.status(400).json({ error: 'Получатель не найден' });
    const msgs = readJSON(MESSAGES_FILE);
    const newMsg = {
        id: Date.now().toString(),
        from: req.session.userId,
        to: recipient.id,
        subject,
        content,
        createdAt: new Date().toISOString(),
        read: false
    };
    msgs.push(newMsg);
    writeJSON(MESSAGES_FILE, msgs);
    createNotification(recipient.id, `Новое ЛС от ${getUsername(req.session.userId)}`, '/messages');
    res.json({ success: true, message: newMsg });
});

// Профиль пользователя
app.get('/api/profile/:username', (req, res) => {
    const users = readJSON(USERS_FILE);
    const user = users.find(u => u.username === req.params.username);
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
    const threads = readJSON(THREADS_FILE);
    const posts = readJSON(POSTS_FILE);
    const threadCount = threads.filter(t => t.authorId === user.id).length;
    const postCount = posts.filter(p => p.authorId === user.id).length;
    res.json({
        username: user.username,
        avatar: user.avatar,
        registeredAt: user.registeredAt,
        role: user.role,
        threadCount,
        postCount
    });
});

// Поиск
app.get('/api/search', (req, res) => {
    const q = req.query.q || '';
    if (!q.trim()) return res.json({ threads: [], posts: [] });
    const threads = readJSON(THREADS_FILE);
    const posts = readJSON(POSTS_FILE);
    const matchedThreads = threads.filter(t => t.title.toLowerCase().includes(q.toLowerCase()) || t.content.toLowerCase().includes(q.toLowerCase()));
    const matchedPosts = posts.filter(p => p.content.toLowerCase().includes(q.toLowerCase()));
    res.json({
        threads: matchedThreads.map(t => ({ ...t, authorName: getUsername(t.authorId) })),
        posts: matchedPosts.map(p => ({ ...p, authorName: getUsername(p.authorId), threadTitle: threads.find(t => t.id === p.threadId)?.title || '' }))
    });
});

// ----- РЕСУРСЫ (публикация) -----
app.post('/api/resources', isAuth, upload.array('screenshots', 10), async (req, res) => {
    const { title, description, downloadLink, version, icon } = req.body;
    if (!title || !description || !downloadLink || !version) {
        return res.status(400).json({ error: 'Заполните все поля' });
    }
    const files = req.files;
    const screenshotPaths = [];
    if (files && files.length > 0) {
        const zipName = `resource_${Date.now()}.zip`;
        const zipPath = path.join(UPLOAD_DIR, zipName);
        const output = fs.createWriteStream(zipPath);
        const archive = archiver('zip', { zlib: { level: 9 } });
        archive.pipe(output);
        files.forEach((file, index) => {
            const ext = path.extname(file.originalname) || '.jpg';
            const fname = `screenshot_${index+1}${ext}`;
            archive.append(file.buffer, { name: fname });
        });
        await new Promise((resolve, reject) => {
            output.on('close', resolve);
            archive.on('error', reject);
            archive.finalize();
        });
        screenshotPaths.push(zipName);
    }
    const resources = readJSON(RESOURCES_FILE);
    const newResource = {
        id: Date.now().toString(),
        title,
        description,
        downloadLink,
        version,
        icon: icon || '',
        screenshots: screenshotPaths,
        authorId: req.session.userId,
        createdAt: new Date().toISOString()
    };
    resources.push(newResource);
    writeJSON(RESOURCES_FILE, resources);
    res.json({ success: true, resource: newResource });
});

app.get('/api/resources', (req, res) => {
    const resources = readJSON(RESOURCES_FILE);
    const enriched = resources.map(r => ({
        ...r,
        authorName: getUsername(r.authorId)
    }));
    res.json(enriched);
});

// ----- АДМИНКА -----
app.get('/api/admin/users', isAuth, isAdmin, (req, res) => {
    const users = readJSON(USERS_FILE);
    res.json(users.map(u => ({ id: u.id, username: u.username, role: u.role, registeredAt: u.registeredAt })));
});
app.delete('/api/admin/users/:id', isAuth, isAdmin, (req, res) => {
    if (req.params.id === req.session.userId) return res.status(403).json({ error: 'Нельзя удалить себя' });
    let users = readJSON(USERS_FILE);
    users = users.filter(u => u.id !== req.params.id);
    writeJSON(USERS_FILE, users);
    res.json({ success: true });
});
app.put('/api/admin/users/:id', isAuth, isAdmin, async (req, res) => {
    const { username, password } = req.body;
    const users = readJSON(USERS_FILE);
    const idx = users.findIndex(u => u.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Пользователь не найден' });
    if (username) users[idx].username = username;
    if (password && password.length >= 6) {
        users[idx].password = await bcrypt.hash(password, 10);
    }
    writeJSON(USERS_FILE, users);
    res.json({ success: true });
});

// Управление стилями
app.get('/api/admin/styles', isAuth, isAdmin, (req, res) => {
    const styles = readJSON(STYLES_FILE);
    res.json(styles);
});
app.put('/api/admin/styles', isAuth, isAdmin, (req, res) => {
    const { style } = req.body;
    if (!style || typeof style !== 'object') return res.status(400).json({ error: 'Неверный формат' });
    writeJSON(STYLES_FILE, style);
    res.json({ success: true });
});

// ----- СТАТИКА -----
app.use(express.static(__dirname));

app.listen(PORT, () => {
    console.log(`Сервер на порту ${PORT}`);
});