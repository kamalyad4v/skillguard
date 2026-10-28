import ollama

if __name__ == "__main__":
    response = ollama.chat(model='gemma:latest', messages=[
        {'role': 'user', 'content': 'Explain what SQL injection is in one sentence.'}
    ])
    print(response['message']['content'])