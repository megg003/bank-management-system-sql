{
 "cells": [
  {
   "cell_type": "code",
   "execution_count": 1,
   "id": "e8383c18",
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "Requirement already satisfied: flask in c:\\users\\rejijose\\anaconda3\\lib\\site-packages (1.1.2)\n",
      "Requirement already satisfied: Werkzeug>=0.15 in c:\\users\\rejijose\\anaconda3\\lib\\site-packages (from flask) (2.0.3)\n",
      "Requirement already satisfied: Jinja2>=2.10.1 in c:\\users\\rejijose\\anaconda3\\lib\\site-packages (from flask) (2.11.3)\n",
      "Requirement already satisfied: itsdangerous>=0.24 in c:\\users\\rejijose\\anaconda3\\lib\\site-packages (from flask) (2.0.1)\n",
      "Requirement already satisfied: click>=5.1 in c:\\users\\rejijose\\anaconda3\\lib\\site-packages (from flask) (8.0.4)\n",
      "Requirement already satisfied: colorama in c:\\users\\rejijose\\anaconda3\\lib\\site-packages (from click>=5.1->flask) (0.4.6)\n",
      "Requirement already satisfied: MarkupSafe>=0.23 in c:\\users\\rejijose\\anaconda3\\lib\\site-packages (from Jinja2>=2.10.1->flask) (2.0.1)\n",
      "Note: you may need to restart the kernel to use updated packages.\n"
     ]
    }
   ],
   "source": [
    "pip install flask"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 2,
   "id": "e1b1ab2b",
   "metadata": {},
   "outputs": [],
   "source": [
    "from flask import Flask"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 4,
   "id": "b31887d7",
   "metadata": {},
   "outputs": [],
   "source": [
    "app=Flask(__name__)\n"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 5,
   "id": "11c223cb",
   "metadata": {},
   "outputs": [],
   "source": [
    "@app.route('/')\n",
    "def homepage():\n",
    "    return '<h1>Hello world</h1>'"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 8,
   "id": "2e79edf1",
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      " * Serving Flask app \"__main__\" (lazy loading)\n",
      " * Environment: production\n",
      "\u001b[31m   WARNING: This is a development server. Do not use it in a production deployment.\u001b[0m\n",
      "\u001b[2m   Use a production WSGI server instead.\u001b[0m\n",
      " * Debug mode: on\n"
     ]
    },
    {
     "name": "stderr",
     "output_type": "stream",
     "text": [
      " * Restarting with watchdog (windowsapi)\n"
     ]
    },
    {
     "ename": "SystemExit",
     "evalue": "1",
     "output_type": "error",
     "traceback": [
      "An exception has occurred, use %tb to see the full traceback.\n",
      "\u001b[1;31mSystemExit\u001b[0m\u001b[1;31m:\u001b[0m 1\n"
     ]
    }
   ],
   "source": [
    "if __name__==\"__main__\":\n",
    "    app.run(host='0.0.0.0',port='8080',debug=True)"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 7,
   "id": "920ffd52",
   "metadata": {},
   "outputs": [
    {
     "ename": "SyntaxError",
     "evalue": "invalid syntax (2008775647.py, line 1)",
     "output_type": "error",
     "traceback": [
      "\u001b[1;36m  File \u001b[1;32m\"C:\\Users\\Rejijose\\AppData\\Local\\Temp\\ipykernel_11996\\2008775647.py\"\u001b[1;36m, line \u001b[1;32m1\u001b[0m\n\u001b[1;33m    flask run\u001b[0m\n\u001b[1;37m          ^\u001b[0m\n\u001b[1;31mSyntaxError\u001b[0m\u001b[1;31m:\u001b[0m invalid syntax\n"
     ]
    }
   ],
   "source": [
    "\n"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 2,
   "id": "a56cf764",
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      " * Serving Flask app \"__main__\" (lazy loading)\n",
      " * Environment: production\n",
      "\u001b[31m   WARNING: This is a development server. Do not use it in a production deployment.\u001b[0m\n",
      "\u001b[2m   Use a production WSGI server instead.\u001b[0m\n",
      " * Debug mode: on\n"
     ]
    },
    {
     "name": "stderr",
     "output_type": "stream",
     "text": [
      " * Running on all addresses.\n",
      "   WARNING: This is a development server. Do not use it in a production deployment.\n",
      " * Running on http://192.168.1.7:8080/ (Press CTRL+C to quit)\n",
      "192.168.1.7 - - [13/Oct/2024 11:17:48] \"GET / HTTP/1.1\" 200 -\n"
     ]
    }
   ],
   "source": [
    "from flask import Flask\n",
    "import nest_asyncio\n",
    "\n",
    "# Apply nest_asyncio to avoid event loop issues\n",
    "nest_asyncio.apply()\n",
    "\n",
    "# Create a Flask application instance\n",
    "app = Flask(__name__)\n",
    "\n",
    "@app.route('/')\n",
    "def homepage():\n",
    "    return 'Hello, World!'\n",
    "\n",
    "# Run the Flask app\n",
    "if __name__ == \"__main__\":\n",
    "    app.run(host='0.0.0.0', port=8080, debug=True, use_reloader=False)\n",
    "\n"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": null,
   "id": "5bb3ad46",
   "metadata": {},
   "outputs": [],
   "source": [
    "from flask import Flask,render_template\n",
    "import nest_asyncio\n",
    "\n",
    "# Apply nest_asyncio to avoid event loop issues\n",
    "nest_asyncio.apply()\n",
    "\n",
    "# Create a Flask application instance\n",
    "app = Flask(__name__)\n",
    "\n",
    "@app.route('/')\n",
    "def homepage():\n",
    "    return render_template('homepage.html')\n",
    "\n",
    "@app.route('/login')\n",
    "def login():\n",
    "    return '<h1>Login Page</h1>'\n",
    "\n",
    "@app.route('/register')\n",
    "def register():\n",
    "    return '<h1>register Page</h1>'\n",
    "\n",
    "@app.route('/deposit')\n",
    "def deposit():\n",
    "    return '<h1>deposit Page</h1>'\n",
    "\n",
    "@app.route('/withdraw')\n",
    "def withdraw():\n",
    "    return '<h1>withdraw Page</h1>'\n",
    "\n",
    "\n",
    "\n",
    "# Run the Flask app\n",
    "if __name__ == \"__main__\":\n",
    "    app.run(host='0.0.0.0', port=8080, debug=True, use_reloader=False)"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": null,
   "id": "19118997",
   "metadata": {},
   "outputs": [],
   "source": []
  }
 ],
 "metadata": {
  "kernelspec": {
   "display_name": "Python 3 (ipykernel)",
   "language": "python",
   "name": "python3"
  },
  "language_info": {
   "codemirror_mode": {
    "name": "ipython",
    "version": 3
   },
   "file_extension": ".py",
   "mimetype": "text/x-python",
   "name": "python",
   "nbconvert_exporter": "python",
   "pygments_lexer": "ipython3",
   "version": "3.9.13"
  }
 },
 "nbformat": 4,
 "nbformat_minor": 5
}
